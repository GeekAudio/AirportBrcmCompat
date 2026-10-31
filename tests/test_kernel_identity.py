#!/usr/bin/env python3
"""Execute structural identity and executable-range checks through a bounded mock no-fault reader."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / 'src/scan_kernel/kernel_identity.cpp'

MOCK = r'''
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <mach/vm_prot.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
bool allocationFails=false,missingHeader=false,missingReader=false,changeDuringCopy=false,shiftedLog=false,shiftedSleep=false;
int allocationCount=0,freeCount=0,readCount=0;
uint8_t *fakeHeader=nullptr;
size_t fakeSize=0;
void *IOMalloc(size_t n){if(allocationFails)return nullptr;++allocationCount;return malloc(n);}
void IOFree(void *p,size_t){++freeCount;free(p);}
vm_size_t fakeRead(vm_offset_t source,vm_offset_t destination,vm_size_t count){
 ++readCount;
 uintptr_t begin=reinterpret_cast<uintptr_t>(fakeHeader);
 if(!begin || source<begin || source-begin>=fakeSize)return 0;
 size_t available=fakeSize-(source-begin);size_t copied=count<available?count:available;
 memcpy(reinterpret_cast<void*>(destination),reinterpret_cast<void*>(source),copied);
 if(changeDuringCopy && count>sizeof(mach_header_64))
  reinterpret_cast<mach_header_64*>(destination)->ncmds++;
 return copied;
}
void IOLog(const char *,...) {}
void IOSleep(unsigned) {}
class KernelPatcher {
public:
 enum class Error {NoError,Missing};
 static constexpr size_t KernelID=0;
 Error error=Error::NoError;
 uintptr_t solveSymbol(size_t id,const char *name){
  assert(id==KernelID);
  if(!strcmp(name,"_IOLog"))return reinterpret_cast<uintptr_t>(&IOLog)+(shiftedLog?0xe8000:0);
  if(!strcmp(name,"_IOSleep"))return reinterpret_cast<uintptr_t>(&IOSleep)+(shiftedSleep?0xe8000:0);
  if(!strcmp(name,"__mh_execute_header")&&!missingHeader)return reinterpret_cast<uintptr_t>(fakeHeader);
  if(!strcmp(name,"_ml_nofault_copy")&&!missingReader)return reinterpret_cast<uintptr_t>(&fakeRead);
  error=Error::Missing;return 0;
 }
 Error getError(){return error;}
 void clearError(){error=Error::NoError;}
};
namespace ScanKernelIdentity {
enum class Profile : uint32_t { Pending=0, Unsupported=1, Structural=2 };
bool copyRunningKernelUUID(uint8_t uuid[16]);
}
'''

HARNESS = r'''
alignas(8) uint8_t storage[16384]{};
void configure(){
 ScanKernelIdentity::sourceState=0;KernelPatcher patcher;ScanKernelIdentity::initialize(patcher);
}
const uint8_t knownButNotAllowlisted[16]={0xa7,0x13,0x42,0x81,0x9c,0x55,0xe2,0x06,
                                           0x70,0xd4,0x33,0x19,0x8b,0xfa,0x61,0x2e};
void setUUID(const uint8_t uuid[16]) {
 auto *h=reinterpret_cast<mach_header_64*>(storage);
 auto *u=reinterpret_cast<uuid_command*>(storage+sizeof(*h));
 memcpy(u->uuid,uuid,16);
}
void reset(){
 memset(storage,0,sizeof(storage));fakeHeader=storage;fakeSize=sizeof(storage);
 auto *h=reinterpret_cast<mach_header_64*>(storage);
 h->magic=MH_MAGIC_64;h->cputype=CPU_TYPE_X86_64;h->filetype=MH_EXECUTE;h->ncmds=2;
 h->sizeofcmds=sizeof(uuid_command)+sizeof(segment_command_64);
 auto *u=reinterpret_cast<uuid_command*>(storage+sizeof(*h));u->cmd=LC_UUID;u->cmdsize=sizeof(uuid_command);
 memcpy(u->uuid,knownButNotAllowlisted,16);
 auto *s=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u));
 s->cmd=LC_SEGMENT_64;s->cmdsize=sizeof(segment_command_64);
 memcpy(s->segname,"__TEXT",6);s->vmaddr=0;s->vmsize=0x1000;s->fileoff=0;s->filesize=0x1000;
 s->maxprot=VM_PROT_READ|VM_PROT_EXECUTE;s->initprot=VM_PROT_READ|VM_PROT_EXECUTE;
 configure();
}
int checkIdentity(int expected,ScanKernelIdentity::Profile expectedOutput,
                  ScanKernelIdentity::Profile expectedCurrent){
 configure();int beforeA=allocationCount,beforeF=freeCount;
 ScanKernelIdentity::Profile profile=ScanKernelIdentity::Profile::Pending;
 int result=ScanKernelIdentity::identifyRunningKernelProfile(&profile);
 assert(result==expected);assert(profile==expectedOutput);
 assert(ScanKernelIdentity::currentProfile()==expectedCurrent);
 assert(allocationCount-beforeA==freeCount-beforeF);
 return result;
}
int main(int argc,char **argv){
 assert(argc==2);std::string mode=argv[1];reset();
 auto *h=reinterpret_cast<mach_header_64*>(storage);
 auto *u=reinterpret_cast<uuid_command*>(storage+sizeof(*h));
 auto *s=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u));
 using Profile=ScanKernelIdentity::Profile;
 if(mode=="unknown_uuid"){
  assert(ScanKernelIdentity::currentProfile()==Profile::Pending);
  uint8_t uuid[16]{};assert(!ScanKernelIdentity::copyRunningKernelUUID(uuid));
  checkIdentity(0,Profile::Structural,Profile::Structural);
  assert(ScanKernelIdentity::verifyRunningKernelIdentity()==0);
  assert(ScanKernelIdentity::copyRunningKernelUUID(uuid));
  assert(!memcmp(uuid,knownButNotAllowlisted,16));
 }else if(mode=="changed_uuid"){
  checkIdentity(0,Profile::Structural,Profile::Structural);
  uint8_t changed[16];memcpy(changed,knownButNotAllowlisted,16);changed[0]^=0x80;setUUID(changed);
  checkIdentity(5,Profile::Unsupported,Profile::Unsupported);
  uint8_t out[16];memset(out,0xaa,sizeof(out));assert(!ScanKernelIdentity::copyRunningKernelUUID(out));
  uint8_t zero[16]{};assert(!memcmp(out,zero,16));
 }else if(mode=="zero_uuid"){
  uint8_t zero[16]{};setUUID(zero);
  checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="duplicate_uuid"){
  auto *dup=reinterpret_cast<uuid_command*>(storage+sizeof(mach_header_64)+sizeof(uuid_command));
  dup->cmd=LC_UUID;dup->cmdsize=sizeof(uuid_command);memcpy(dup->uuid,knownButNotAllowlisted,16);
  s=reinterpret_cast<segment_command_64*>(storage+sizeof(mach_header_64)+2*sizeof(uuid_command));
  s->cmd=LC_SEGMENT_64;s->cmdsize=sizeof(segment_command_64);memcpy(s->segname,"__TEXT",6);
  s->vmsize=0x1000;s->filesize=0x1000;s->maxprot=VM_PROT_READ|VM_PROT_EXECUTE;s->initprot=s->maxprot;
  h->ncmds=3;h->sizeofcmds=2*sizeof(uuid_command)+sizeof(segment_command_64);
  fakeSize=sizeof(mach_header_64)+h->sizeofcmds;
  checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="header"){
  h->magic=0;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();h->cputype=CPU_TYPE_ARM64;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();h->filetype=MH_FILESET;checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="commands"){
  u->cmdsize=0;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();u->cmdsize=25;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();h->sizeofcmds=25;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();h->ncmds=4;checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="segments"){
  s->cmdsize=sizeof(load_command);h->sizeofcmds=sizeof(uuid_command)+sizeof(load_command);
  fakeSize=sizeof(mach_header_64)+h->sizeofcmds;checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();s=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u));s->nsects=1;
  checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();s=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u));s->filesize=s->vmsize+1;
  checkIdentity(5,Profile::Unsupported,Profile::Pending);
  reset();s=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u));
  s->vmaddr=UINT64_MAX-0x100;s->vmsize=0x200;checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="acquire"){
  allocationFails=true;checkIdentity(3,Profile::Unsupported,Profile::Pending);allocationFails=false;
  missingReader=true;checkIdentity(4,Profile::Unsupported,Profile::Pending);missingReader=false;
  missingHeader=true;checkIdentity(4,Profile::Unsupported,Profile::Pending);missingHeader=false;
  fakeHeader=nullptr;checkIdentity(4,Profile::Unsupported,Profile::Pending);
  reset();fakeSize=sizeof(mach_header_64)-1;checkIdentity(4,Profile::Unsupported,Profile::Pending);
 }else if(mode=="alignment"){
  fakeHeader=storage+1;checkIdentity(4,Profile::Unsupported,Profile::Pending);
 }else if(mode=="overflow"){
  fakeHeader=reinterpret_cast<uint8_t*>(UINTPTR_MAX-7U);fakeSize=64;
  checkIdentity(4,Profile::Unsupported,Profile::Pending);
 }else if(mode=="window"){
  fakeSize=sizeof(storage);h->sizeofcmds=65536;h->ncmds=1;
  checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="guarded"){
  long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
  void *area=mmap(nullptr,static_cast<size_t>(page)*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(area!=MAP_FAILED);assert(!mprotect(static_cast<uint8_t*>(area)+page,static_cast<size_t>(page),PROT_NONE));
  fakeSize=sizeof(mach_header_64)+h->sizeofcmds;
  fakeHeader=static_cast<uint8_t*>(area)+page-fakeSize;memcpy(fakeHeader,storage,fakeSize);
  checkIdentity(0,Profile::Structural,Profile::Structural);
  reinterpret_cast<mach_header_64*>(fakeHeader)->sizeofcmds+=8;
  checkIdentity(4,Profile::Unsupported,Profile::Structural);
  assert(!munmap(area,static_cast<size_t>(page)*2));
 }else if(mode=="code_range"){
  fakeSize=sizeof(storage);
  uintptr_t base=reinterpret_cast<uintptr_t>(storage);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0x100,16)==0);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0xff0,16)==0);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0xfff,2)==6);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0x100,0)==6);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(UINTPTR_MAX-1,4)==6);
 }else if(mode=="nonexec_range"){
  s->initprot=VM_PROT_READ;s->maxprot=VM_PROT_READ;
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(reinterpret_cast<uintptr_t>(storage)+0x100,8)==6);
 }else if(mode=="malformed_range"){
  s->nsects=1;
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(reinterpret_cast<uintptr_t>(storage)+0x100,8)==5);
 }else if(mode=="guarded_range"){
  long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
  void *area=mmap(nullptr,static_cast<size_t>(page)*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(area!=MAP_FAILED);assert(!mprotect(static_cast<uint8_t*>(area)+page,static_cast<size_t>(page),PROT_NONE));
  s->vmsize=128;s->filesize=128;fakeSize=128;
  fakeHeader=static_cast<uint8_t*>(area)+page-fakeSize;memcpy(fakeHeader,storage,fakeSize);
  configure();uintptr_t base=reinterpret_cast<uintptr_t>(fakeHeader);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0x70,8)==0);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0x7f,2)==6);
  assert(!munmap(area,static_cast<size_t>(page)*2));
 }else if(mode=="readable_range"){
  auto *data=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u)+sizeof(*s));
  data->cmd=LC_SEGMENT_64;data->cmdsize=sizeof(segment_command_64);memcpy(data->segname,"__DATA",6);
  data->vmaddr=0x1000;data->vmsize=0x1000;data->fileoff=0;data->filesize=0;
  data->initprot=VM_PROT_READ;data->maxprot=VM_PROT_READ|VM_PROT_WRITE;
  h->ncmds=3;h->sizeofcmds+=sizeof(segment_command_64);fakeSize=sizeof(storage);
  uintptr_t base=reinterpret_cast<uintptr_t>(storage);
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(base+0x1100,16)==0);
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(base+0x1100,16)==6);
  data->initprot=VM_PROT_EXECUTE;data->maxprot=VM_PROT_EXECUTE;
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(base+0x1100,16)==6);
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(UINTPTR_MAX-1,4)==6);
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(base+sizeof(storage)-1,2)==6);
 }else if(mode=="guarded_readable_range"){
  long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
  void *area=mmap(nullptr,static_cast<size_t>(page)*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(area!=MAP_FAILED);assert(!mprotect(static_cast<uint8_t*>(area)+page,static_cast<size_t>(page),PROT_NONE));
  const size_t mapped=256;fakeSize=mapped;
  auto *data=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u)+sizeof(*s));
  data->cmd=LC_SEGMENT_64;data->cmdsize=sizeof(segment_command_64);memcpy(data->segname,"__DATA",6);
  data->vmaddr=0x1000;data->vmsize=0x1000;data->initprot=VM_PROT_READ;data->maxprot=VM_PROT_READ;
  h->ncmds=3;h->sizeofcmds+=sizeof(segment_command_64);
  auto *image=static_cast<uint8_t*>(area)+page-mapped;memcpy(image,storage,sizeof(mach_header_64)+h->sizeofcmds);
  fakeHeader=image;configure();uintptr_t base=reinterpret_cast<uintptr_t>(image);
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(base+0x10f8,16)==6);
  assert(!munmap(area,static_cast<size_t>(page)*2));
 }else if(mode=="file_only_segment"){
  auto *debug=reinterpret_cast<segment_command_64*>(storage+sizeof(*h)+sizeof(*u)+sizeof(*s));
  debug->cmd=LC_SEGMENT_64;debug->cmdsize=sizeof(*debug)+sizeof(section_64);
  memcpy(debug->segname,"__CTF",5);debug->vmaddr=0x3000;debug->vmsize=0;
  debug->fileoff=0x10000;debug->filesize=0x200;debug->nsects=1;
  debug->initprot=VM_PROT_READ;debug->maxprot=VM_PROT_READ;
  auto *section=reinterpret_cast<section_64*>(debug+1);
  section->addr=debug->vmaddr;section->size=0x180;section->offset=debug->fileoff;
  h->ncmds=3;h->sizeofcmds+=debug->cmdsize;
  checkIdentity(0,Profile::Structural,Profile::Structural);
  uintptr_t base=reinterpret_cast<uintptr_t>(storage);
  assert(ScanKernelIdentity::verifyRunningKernelReadableRange(base+0x3000,1)==6);
  section->size=0x201;checkIdentity(5,Profile::Unsupported,Profile::Unsupported);
 }else if(mode=="torn_header"){
  changeDuringCopy=true;checkIdentity(5,Profile::Unsupported,Profile::Pending);
 }else if(mode=="uninitialized"){
  ScanKernelIdentity::sourceState=0;
  assert(ScanKernelIdentity::verifyRunningKernelIdentity()==4);
 }else if(mode=="initialization_once"){
  auto before=ScanKernelIdentity::kernelHeader;KernelPatcher p;fakeHeader=nullptr;
  assert(ScanKernelIdentity::initialize(p)==0);assert(ScanKernelIdentity::kernelHeader==before);
 }else if(mode=="shifted_symbols"){
  int before=readCount;shiftedLog=true;
  checkIdentity(4,Profile::Unsupported,Profile::Pending);assert(readCount==before);
  shiftedLog=false;shiftedSleep=true;
  checkIdentity(4,Profile::Unsupported,Profile::Pending);assert(readCount==before);
 }else if(mode=="partial_copy"){
  fakeSize=sizeof(mach_header_64)+h->sizeofcmds-1;
  checkIdentity(4,Profile::Unsupported,Profile::Pending);
 }else if(mode=="unmapped_probe"){
  fakeSize=0x200;
  assert(ScanKernelIdentity::verifyRunningKernelCodeRange(reinterpret_cast<uintptr_t>(storage)+0x800,16)==6);
 }else assert(false);
 puts("mock-only structural identity scenario passed");
}
'''


class KernelIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='skyscan-kernel-identity-offline-', dir='/private/tmp')
        source = '\n'.join(line for line in SOURCE.read_text().splitlines() if not line.startswith('#include '))
        cpp = Path(cls.work.name) / 'identity_mock.cpp'
        cpp.write_text(MOCK + '\n' + source + '\n' + HARNESS)
        cls.binary = Path(cls.work.name) / 'identity_mock'
        built = subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                                str(cpp), '-o', str(cls.binary)],
                               capture_output=True, text=True, timeout=30)
        if built.returncode:
            cls.work.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls): cls.work.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('mock-only structural identity scenario passed', result.stdout)

    def test_unknown_nonzero_uuid_is_structural_not_a_build_allowlist(self): self.scenario('unknown_uuid')
    def test_changed_uuid_during_run_is_rejected_and_poisoned(self): self.scenario('changed_uuid')
    def test_zero_or_duplicate_uuid_is_rejected(self):
        self.scenario('zero_uuid')
        self.scenario('duplicate_uuid')
    def test_invalid_header_and_command_bounds_are_rejected(self):
        self.scenario('header')
        self.scenario('commands')
    def test_malformed_segment_layout_is_rejected(self): self.scenario('segments')
    def test_file_only_debug_segment_is_valid_but_never_a_runtime_range(self): self.scenario('file_only_segment')
    def test_acquisition_alignment_and_pointer_overflow(self):
        self.scenario('acquire')
        self.scenario('alignment')
        self.scenario('overflow')
    def test_torn_header_partial_reads_and_missing_initialization(self):
        self.scenario('torn_header')
        self.scenario('partial_copy')
        self.scenario('uninitialized')
        self.scenario('initialization_once')
        self.scenario('unmapped_probe')
        self.scenario('shifted_symbols')
    def test_mach_header_window_is_capped(self): self.scenario('window')
    def test_exact_header_boundary_has_inaccessible_guard_page(self): self.scenario('guarded')
    def test_executable_segment_range_and_boundaries(self): self.scenario('code_range')
    def test_non_executable_and_malformed_segments_are_refused(self):
        self.scenario('nonexec_range')
        self.scenario('malformed_range')
    def test_code_range_does_not_read_past_header_boundary(self): self.scenario('guarded_range')
    def test_readable_and_executable_segment_permissions(self): self.scenario('readable_range')
    def test_readable_range_is_bounded_by_mapped_image(self): self.scenario('guarded_readable_range')


if __name__ == '__main__': unittest.main()
