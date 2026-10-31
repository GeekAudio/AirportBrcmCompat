#!/usr/bin/env python3
"""Execute current identity verifier with fake MachInfo, never a kernel API."""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / 'src/scan_kernel/kernel_identity.cpp'

MOCK = r'''
#include <mach-o/loader.h>
#include <mach/machine.h>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cstdlib>
#include <cassert>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
bool allocationFails=false;
int addressResult=0, createCount=0, positionCount=0, deinitCount=0, deleteCount=0;
uint8_t *fakeHeader=nullptr;
size_t fakeSize=0;
namespace ScanKernelIdentity {
enum class Profile : uint32_t { Unsupported=0, Build25G241=1, Build25G332=2 };
}
struct MachInfo {
 uint8_t mockStorage[192]{};
 static constexpr size_t HeaderSize=8192;
 static MachInfo *create(bool asKernel,const char *id){++createCount;assert(asKernel&&std::string(id)=="kernel");return allocationFails?nullptr:new MachInfo;}
 int getRunningAddresses(){return addressResult;}
 void getRunningPosition(uint8_t *&header,size_t &size){++positionCount;header=fakeHeader;size=fakeSize;}
 void deinit(){++deinitCount;}
 static void deleter(MachInfo *p){++deleteCount;delete p;}
};
'''
HARNESS = r'''
alignas(8) uint8_t storage[16384]{};
void reset(){
 memset(storage,0,sizeof(storage));fakeHeader=storage;fakeSize=56;
 auto *h=reinterpret_cast<mach_header_64*>(storage);
 h->magic=MH_MAGIC_64;h->cputype=CPU_TYPE_X86_64;h->filetype=MH_EXECUTE;h->ncmds=1;h->sizeofcmds=24;
 auto *u=reinterpret_cast<uuid_command*>(storage+32);u->cmd=LC_UUID;u->cmdsize=24;
 const uint8_t expected[]={0x12,0x91,0xd4,0x4a,0xc0,0xcd,0x3a,0xc7,0xa9,0xe4,0xca,0x27,0x49,0xb3,0x39,0x59};
 memcpy(u->uuid,expected,16);
}
void check(int expected,ScanKernelIdentity::Profile expectedProfile=ScanKernelIdentity::Profile::Unsupported){
 int beforeD=deinitCount,beforeF=deleteCount,beforeP=positionCount;
 auto profileBefore=ScanKernelIdentity::currentProfile();
 ScanKernelIdentity::Profile profile=ScanKernelIdentity::Profile::Build25G332;
 assert(ScanKernelIdentity::identifyRunningKernelProfile(&profile)==expected);
 assert(profile==expectedProfile);
 if(expected==0)assert(ScanKernelIdentity::currentProfile()==expectedProfile);
 else assert(ScanKernelIdentity::currentProfile()==profileBefore);
 assert(deinitCount-beforeD==int(!allocationFails));
 assert(deleteCount-beforeF==int(!allocationFails));
 if(allocationFails||addressResult)assert(positionCount==beforeP);
}
int main(int argc,char **argv){
 assert(argc==2);std::string mode=argv[1];reset();
 auto *h=reinterpret_cast<mach_header_64*>(storage);
 auto *u=reinterpret_cast<uuid_command*>(storage+32);
 if(mode=="valid"){
  check(0,ScanKernelIdentity::Profile::Build25G241);reset();memmove(storage+40,storage+32,24);h->ncmds=2;h->sizeofcmds=32;fakeSize=64;
  auto *c=reinterpret_cast<load_command*>(storage+32);c->cmd=0x777;c->cmdsize=8;check(0,ScanKernelIdentity::Profile::Build25G241);
 }else if(mode=="332"){
  const uint8_t expected[]={0x28,0x26,0x7f,0xd5,0x3e,0x1e,0x36,0x86,0x8a,0x1c,0xe7,0x3e,0x24,0x66,0xfc,0xfb};
  memcpy(u->uuid,expected,16);check(0,ScanKernelIdentity::Profile::Build25G332);
  assert(ScanKernelIdentity::verifyRunningKernelIdentity()==0);
 }else if(mode=="reject332"){
  const uint8_t expected[]={0x28,0x26,0x7f,0xd5,0x3e,0x1e,0x36,0x86,0x8a,0x1c,0xe7,0x3e,0x24,0x66,0xfc,0xfb};
  memcpy(u->uuid,expected,16);check(5);
 }else if(mode=="reject241"){
  check(5);
 }else if(mode=="uuid"){
  u->uuid[15]^=1;check(5);reset();u->cmd=0x777;check(5);
 }else if(mode=="duplicate"){
  memcpy(storage+56,storage+32,24);h->ncmds=2;h->sizeofcmds=48;fakeSize=80;check(5);
 }else if(mode=="header"){
  h->magic=0;check(5);reset();h->cputype=CPU_TYPE_ARM64;check(5);reset();h->filetype=MH_FILESET;check(5);
 }else if(mode=="counts"){
  h->sizeofcmds=25;check(5);reset();h->ncmds=4;check(5);reset();h->sizeofcmds=32;fakeSize=64;check(5);
 }else if(mode=="commands"){
  for(uint32_t size:{0U,7U,9U,32U}){reset();u->cmdsize=size;check(5);}
  reset();u->cmdsize=16;h->sizeofcmds=16;fakeSize=48;check(5);
 }else if(mode=="acquire"){
  allocationFails=true;check(3);allocationFails=false;addressResult=5;check(4);addressResult=0;
  fakeHeader=nullptr;check(4);reset();fakeSize=31;check(4);
 }else if(mode=="alignment"){
  fakeHeader=storage+1;check(4);
 }else if(mode=="overflow"){
  fakeHeader=reinterpret_cast<uint8_t*>(UINTPTR_MAX-7U);fakeSize=64;check(4);
 }else if(mode=="window"){
  fakeSize=sizeof(storage);h->sizeofcmds=8192;h->ncmds=1;check(5);
 }else if(mode=="guarded"){
  long page=sysconf(_SC_PAGESIZE);assert(page>=4096);
  void *area=mmap(nullptr,static_cast<size_t>(page)*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
  assert(area!=MAP_FAILED);assert(!mprotect(static_cast<uint8_t*>(area)+page,static_cast<size_t>(page),PROT_NONE));
  fakeHeader=static_cast<uint8_t*>(area)+page-56;memcpy(fakeHeader,storage,56);fakeSize=56;
  check(0,ScanKernelIdentity::Profile::Build25G241);
  reinterpret_cast<mach_header_64*>(fakeHeader)->sizeofcmds=32;check(5);
  assert(!munmap(area,static_cast<size_t>(page)*2));
 }else assert(false);
 puts("mock-only identity scenario passed");
}
'''


class KernelIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='skyscan-kernel-identity-offline-', dir='/private/tmp')
        source = '\n'.join(line for line in SOURCE.read_text().splitlines() if not line.startswith('#include '))
        cpp = Path(cls.work.name) / 'identity_mock.cpp'
        cpp.write_text(MOCK + '\n' + source + '\n' + HARNESS)
        cls.binaries = {}
        for name, flags in [('dual', ['-DAIRPORT_BRCM_DUAL_PROFILE_25G241_25G332=1']),
                            ('single241', []),
                            ('single332', ['-DAIRPORT_BRCM_BASELINE_25G332=1'])]:
            binary = Path(cls.work.name) / ('identity_mock_' + name)
            built = subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                                    *flags, str(cpp), '-o', str(binary)],
                                   capture_output=True, text=True, timeout=30)
            if built.returncode:
                cls.work.cleanup()
                raise AssertionError(built.stderr)
            cls.binaries[name] = binary

    @classmethod
    def tearDownClass(cls): cls.work.cleanup()

    def scenario(self, name, profile='dual'):
        result = subprocess.run([str(self.binaries[profile]), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('mock-only identity scenario passed', result.stdout)

    def test_exact_inner_uuid_and_nonfirst_command(self): self.scenario('valid')
    def test_exact_25g332_inner_uuid_selects_its_profile(self): self.scenario('332')
    def test_single_profile_builds_reject_the_other_known_uuid(self):
        self.scenario('valid', 'single241')
        self.scenario('reject332', 'single241')
        self.scenario('332', 'single332')
        self.scenario('reject241', 'single332')
    def test_wrong_or_missing_uuid(self): self.scenario('uuid')
    def test_duplicate_uuid_refused(self): self.scenario('duplicate')
    def test_magic_cpu_and_outer_fileset_refused(self): self.scenario('header')
    def test_command_counts_and_trailing_bytes_refused(self): self.scenario('counts')
    def test_invalid_command_sizes_refused(self): self.scenario('commands')
    def test_acquisition_errors_and_cleanup(self): self.scenario('acquire')
    def test_unaligned_header_refused(self): self.scenario('alignment')
    def test_pointer_range_overflow_refused(self): self.scenario('overflow')
    def test_header_window_is_capped(self): self.scenario('window')
    def test_exact_boundary_has_inaccessible_guard_page(self): self.scenario('guarded')


if __name__ == '__main__': unittest.main()
