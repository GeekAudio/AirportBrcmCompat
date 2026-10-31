"""Offline owned buffers only: fixed bounds, privacy invariance, no admission change."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include "association_survey.hpp"
#include "association_compat.hpp"
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
#include <thread>
#include <vector>
using namespace AssociationSurvey;
static uint32_t join(Word32 x){return uint32_t(x.low16)|(uint32_t(x.high16)<<16);}
static void put32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=uint8_t(v>>(i*8));}
static void put16(uint8_t *p,uint16_t v){p[0]=uint8_t(v);p[1]=uint8_t(v>>8);}
static bool same(const Snapshot &a,const Snapshot &b){return !memcmp(&a,&b,sizeof(a));}
static bool visible(size_t p){
 return (p>=8&&p<16)||(p>=508&&p<512)||p==518||(p>=580&&p<584)||
        (p>=624&&p<642)||(p>=64&&p<72)||(p>=472&&p<476)||
        (p>=208&&p<210)||p==899||p>=900;
}
static void scalars(){
 uint8_t raw[NativeSize+2]{};uint8_t *in=raw+1; // deliberately unaligned
 const size_t offsets[]={8,12,508,580,624,628,632,636,64,68,472};
 const uint32_t values[]={0xffffffffU,0x80000000U,0x40000004U,0xffffffffU,
                          0x12345678U,0x80008000U,0xfedcba98U,0x00030000U,
                          0xffffffffU,0xffff000aU,0x80000020U};
 for(size_t j=0;j<11;j++)put32(in+offsets[j],values[j]);
 in[518]=255;put16(in+640,65535);put16(in+208,65535);in[899]=255;
 uint8_t before[NativeSize];memcpy(before,in,NativeSize);Snapshot out;
 assert(inspect(in,NativeSize,out)==Status::Ok);
 const Word32 words[]={out.authLower8,out.authUpper12,out.allowedAuth508,out.scopeLength580,
  out.authUpperExt624,out.transitionDisabledFlags628,out.bandPreference632,out.wsecFlags636,
  out.keyLength64,out.cipher68,out.pmkLength472};
 for(size_t j=0;j<11;j++){assert(join(words[j])==values[j]);
  assert(int32_t(words[j].low16)!=-1&&int32_t(words[j].high16)!=-1);}
 assert(out.denyListedBSSIDCount518==255&&out.secondIELength640==65535&&out.sixGPolicy899==255&&out.firstIELength208==65535);
 assert(!out.unknownTailFirstOffset&&!out.unknownTailNonzero&&!memcmp(in,before,NativeSize));
 // Lengths never govern access: all-ones lengths are observable metadata only.
 for(unsigned n=0;n<256;n++){in[518]=uint8_t(n);in[899]=uint8_t(n);
  assert(inspect(in,NativeSize,out)==Status::Ok);
  assert(out.denyListedBSSIDCount518==n&&out.sixGPolicy899==n);}
}
static void allOffsets(){
 const Snapshot zero{};
 for(size_t offset=0;offset<NativeSize;offset++){
  uint8_t in[NativeSize]{};in[offset]=1;Snapshot out;
  assert(inspect(in,sizeof(in),out)==Status::Ok);
  if(!visible(offset)){assert(same(out,zero));continue;}
  if(offset<900){assert(!same(out,zero));assert(!out.unknownTailNonzero&&!out.unknownTailFirstOffset);}
  else {assert(out.unknownTailNonzero==1&&out.unknownTailFirstOffset==offset);
    Snapshot expected{};expected.unknownTailNonzero=1;expected.unknownTailFirstOffset=uint16_t(offset);
    assert(same(out,expected));
    for(unsigned value: {2U,128U,255U}){in[offset]=uint8_t(value);Snapshot changed;
     assert(inspect(in,sizeof(in),changed)==Status::Ok&&same(changed,out));}}
 }
 uint8_t in[NativeSize]{};in[900]=1;in[907]=255;Snapshot out;
 assert(inspect(in,sizeof(in),out)==Status::Ok&&out.unknownTailFirstOffset==900&&out.unknownTailNonzero==1);
}
static void identityInvariance(){
 uint8_t in[NativeSize]{};
 put32(in+8,1);put32(in+12,8);put32(in+508,0x40000004);
 put32(in+580,36);put32(in+624,1);put32(in+628,2);put32(in+632,3);put32(in+636,0x30000);
 in[518]=7;put16(in+640,257);in[899]=2;in[905]=1;
 Snapshot expected;assert(inspect(in,sizeof(in),expected)==Status::Ok);
 // Every byte outside the documented numeric allowlist is independently varied
 // through all256 values, including SSID, all MACs, scope, keys and both IEs.
 for(size_t offset=0;offset<NativeSize;offset++)if(!visible(offset)){
  for(unsigned value=0;value<256;value++){
   in[offset]=uint8_t(value);Snapshot out;
   assert(inspect(in,sizeof(in),out)==Status::Ok&&same(out,expected));
  }in[offset]=0;
 }
 // Simultaneously change the entire protected payload, not only one byte.
 for(unsigned round=0;round<256;round++){
  for(size_t p=0;p<NativeSize;p++)if(!visible(p))in[p]=uint8_t(round+p*73);
  Snapshot out;assert(inspect(in,sizeof(in),out)==Status::Ok&&same(out,expected));
 }
}
static void bounds(){
 const size_t page=size_t(sysconf(_SC_PAGESIZE));assert(page>=NativeSize);
 auto *mapping=static_cast<uint8_t*>(mmap(nullptr,page*3,PROT_NONE,MAP_ANON|MAP_PRIVATE,-1,0));
 assert(mapping!=MAP_FAILED);assert(!mprotect(mapping+page,page,PROT_READ|PROT_WRITE));
 uint8_t *in=mapping+page*2-NativeSize;memset(in,0,NativeSize);in[907]=1;
 assert(!mprotect(mapping+page,page,PROT_READ));
 Snapshot out;assert(inspect(in,NativeSize,out)==Status::Ok&&out.unknownTailFirstOffset==907);
 for(size_t n=0;n<NativeSize;n++){
  out.unknownTailFirstOffset=65535;
  assert(inspect(in,n,out)==Status::InvalidInput&&same(out,Snapshot{}));
 }
 for(size_t n: {NativeSize+1,NativeSize+64}){
  assert(inspect(in,n,out)==Status::InvalidInput&&same(out,Snapshot{}));
 }
 assert(inspect(nullptr,NativeSize,out)==Status::InvalidInput&&same(out,Snapshot{}));
 // If a caller aliases a read-only input, even invalid-length refusal must not
 // write a zeroed Snapshot through that address.
 auto &aliased=*reinterpret_cast<Snapshot*>(in);
 assert(inspect(in,NativeSize,aliased)==Status::AliasedOutput);
 assert(inspect(in,0,aliased)==Status::AliasedOutput);
 assert(!munmap(mapping,page*3));
 alignas(Snapshot) uint8_t storage[NativeSize+sizeof(Snapshot)+8];memset(storage,0xa7,sizeof(storage));
 uint8_t before[sizeof(storage)];memcpy(before,storage,sizeof(storage));
 for(size_t offset: {size_t(0),size_t(8),size_t(512),size_t(864)}){
  auto &target=*reinterpret_cast<Snapshot*>(storage+offset);
  assert(inspect(storage,NativeSize,target)==Status::AliasedOutput);
  assert(!memcmp(storage,before,sizeof(storage)));
 }
 // Exactly adjacent output is permitted and cannot change the input bytes.
 auto &adjacent=*reinterpret_cast<Snapshot*>(storage+NativeSize);
 assert(inspect(storage,NativeSize,adjacent)==Status::Ok);
 assert(!memcmp(storage,before,NativeSize));
}
static void admissionUnchanged(){
 for(unsigned mode=0;mode<10;mode++){
  uint8_t in[NativeSize]{},before[NativeSize],oldA[548],oldB[548];
  put32(in,1);put16(in+4,2);put32(in+8,1);put32(in+16,3);
  in[20]=1;in[21]=2;in[22]=3;in[899]=2;
  if(mode){put32(in+12,8);put32(in+60,1);put32(in+64,32);put32(in+68,6);memset(in+76,0x9b,32);}
  if(mode>=2){in[468]=8;in[512]=6;for(size_t p=513;p<518;p++)in[p]=uint8_t(p);}
  if(mode==3)in[469]=64;
  if(mode==4)put32(in+508,0x40000004U);
  if(mode==5)in[900]=1;
  if(mode==6)put32(in+580,36);
  if(mode==7)put16(in+640,257);
  if(mode==8)in[518]=7;
  if(mode==9)in[12]=0x80;
  memcpy(before,in,sizeof(in));memset(oldA,0x59,sizeof(oldA));memset(oldB,0x59,sizeof(oldB));
  PrivateMAC::NativeRequest a,b;
  auto first=AssociationCompat::convert(in,sizeof(in),oldA,sizeof(oldA),&a);
  Snapshot survey;assert(inspect(in,sizeof(in),survey)==Status::Ok);
  auto second=AssociationCompat::convert(in,sizeof(in),oldB,sizeof(oldB),&b);
  assert(first.error==second.error&&first.field==second.field&&!memcmp(oldA,oldB,sizeof(oldA)));
  assert(a.requested==b.requested&&a.deviceTypeInDhcpAllowed==b.deviceTypeInDhcpAllowed&&!memcmp(a.address,b.address,6));
  assert(!memcmp(in,before,sizeof(in)));
 }
}
static void concurrency(){
 std::vector<std::thread> threads;
 for(unsigned id=0;id<8;id++)threads.emplace_back([id]{
  for(unsigned trial=0;trial<1000;trial++){
   uint8_t in[NativeSize]{};put32(in+508,0x40000004U+id);put32(in+580,trial);
   memset(in+519,int(id+trial),61);memset(in+584,int(id+trial),40);memset(in+642,int(id+trial),257);
   in[518]=uint8_t(id);in[899]=2;in[900+id]=uint8_t(trial%255+1);
   uint8_t before[NativeSize];memcpy(before,in,sizeof(in));Snapshot out;
   assert(inspect(in,sizeof(in),out)==Status::Ok&&join(out.allowedAuth508)==0x40000004U+id);
   assert(join(out.scopeLength580)==trial&&out.denyListedBSSIDCount518==id);
   assert(out.unknownTailFirstOffset==900+id&&out.unknownTailNonzero==1&&!memcmp(in,before,sizeof(in)));
  }
 });
 for(auto &t:threads)t.join();
}
int main(int argc,char **argv){assert(argc==2);switch(atoi(argv[1])){
 case 0:scalars();break;case 1:allOffsets();break;case 2:identityInvariance();break;
 case 3:bounds();break;case 4:admissionUnchanged();break;case 5:concurrency();break;default:abort();}}
'''


class AssociationSurveyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix="association-survey-",dir="/private/tmp")
        cls.binary=pathlib.Path(cls.tmp.name)/"test"
        value=subprocess.run(["xcrun","clang++","-std=c++14","-Wall","-Wextra","-Werror",
                              "-fsanitize=address,undefined","-fno-omit-frame-pointer","-pthread",
                              "-I",str(PROJECT/"src/scan_kernel"),"-x","c++","-","-o",str(cls.binary)],
                             input=HARNESS,text=True,capture_output=True,timeout=60)
        if value.returncode:
            raise AssertionError(value.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self,n):
        value=subprocess.run([str(self.binary),str(n)],text=True,capture_output=True,timeout=30)
        self.assertEqual(value.returncode,0,value.stderr)

    def test_exact_little_endian_policy_scalars_and_no_signed_sentinel(self):self.scenario(0)
    def test_every_offset_uses_only_the_fixed_metadata_allowlist(self):self.scenario(1)
    def test_all_identity_key_scope_and_ie_byte_values_leave_survey_invariant(self):self.scenario(2)
    def test_guard_pages_readonly_input_invalid_sizes_and_output_aliasing(self):self.scenario(3)
    def test_survey_never_changes_converter_admission_or_owned_plan(self):self.scenario(4)
    def test_eight_threads_share_no_state_or_payload(self):self.scenario(5)


if __name__=="__main__":
    unittest.main()
