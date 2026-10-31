"""Actual portable headers, fictional payloads, no kernel or network calls."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "association_compat.hpp"
#include <assert.h>
#include <stdlib.h>
#include <new>
#include <initializer_list>
using PrivateMAC::NativeRequest;
constexpr size_t N=AssociationCompat::NativeSize,O=AssociationCompat::LegacySize;
static const uint8_t address[6]={6,0x24,0x31,0x42,0x53,0x64}; // Fictional; never logged.
static void put32(uint8_t *p,uint32_t x){memcpy(p,&x,4);}
static void init(uint8_t *p,bool privateFlag=true,bool dhcpAllowed=false){
 memset(p,0,N);put32(p,1);ScanCompat::write16(p+4,2);put32(p+8,1);
 put32(p+12,8);put32(p+16,3);memcpy(p+20,"abc",3);put32(p+60,1);
 put32(p+64,32);put32(p+68,6);memset(p+76,0x3c,32);put32(p+508,4);p[899]=2;
 if(privateFlag){p[468]=8;memcpy(p+512,address,6);}
 p[469]=dhcpAllowed?0x40:0;
}
static void seed(NativeRequest &p){p.requested=true;p.deviceTypeInDhcpAllowed=true;memset(p.address,0xa5,6);}
static void empty(const NativeRequest &p){assert(!p.requested&&!p.deviceTypeInDhcpAllowed);for(auto x:p.address)assert(!x);}
static void first_byte(){
 for(unsigned policy=0;policy<2;policy++)for(unsigned first=0;first<256;first++){
  uint8_t in[N],before[N],old[O],saved[O];init(in,true,policy);in[512]=(uint8_t)first;
  memcpy(before,in,N);memset(old,0x5c,O);memcpy(saved,old,O);NativeRequest parsed,plan;seed(parsed);seed(plan);
  const bool valid=(first&3U)==2U;
  auto p=PrivateMAC::parseNative(in,N,parsed);auto c=AssociationCompat::convert(in,N,old,O,&plan);
  if(valid){assert(!p.error&&!c.error&&parsed.requested&&plan.requested);
   assert(parsed.deviceTypeInDhcpAllowed==(policy!=0)&&plan.deviceTypeInDhcpAllowed==(policy!=0));
   assert(!memcmp(parsed.address,in+512,6)&&!memcmp(plan.address,in+512,6));assert(!(old[464]&8)&&!(old[465]&0x40));}
  else{assert(p.error==EINVAL&&p.field==512&&c.error==EINVAL&&c.field==512);
   empty(parsed);empty(plan);assert(!memcmp(old,saved,O));}
  assert(!memcmp(in,before,N));
 }
}
static void unsupported_flags(){
 for(size_t field=469;field<472;field++)for(unsigned value=1;value<256;value++){
  uint8_t in[N],before[N],old[O],saved[O];init(in);in[field]=(uint8_t)value;
  memcpy(before,in,N);memset(old,0x5c,O);memcpy(saved,old,O);NativeRequest parsed,plan;seed(parsed);seed(plan);
  auto p=PrivateMAC::parseNative(in,N,parsed);auto c=AssociationCompat::convert(in,N,old,O,&plan);
  if(field==469&&value==0x40){
   assert(!p.error&&!c.error&&parsed.requested&&plan.requested);
   assert(parsed.deviceTypeInDhcpAllowed&&plan.deviceTypeInDhcpAllowed);
   assert(!memcmp(parsed.address,address,6)&&!memcmp(plan.address,address,6)&&!(old[465]&0x40));
  }else{
   assert(p.error==EOPNOTSUPP&&p.field==field&&c.error==EOPNOTSUPP&&c.field==field);
   empty(parsed);empty(plan);assert(!memcmp(old,saved,O));
  }
  assert(!memcmp(in,before,N));
 }
 // DHCP policy cannot travel without a private-address consumer/request.
 uint8_t in[N],before[N],old[O],saved[O];init(in,false,true);memcpy(before,in,N);
 memset(old,0x5c,O);memcpy(saved,old,O);NativeRequest p;seed(p);
 auto parsed=PrivateMAC::parseNative(in,N,p);assert(parsed.error==EOPNOTSUPP&&parsed.field==469);empty(p);
 seed(p);auto converted=AssociationCompat::convert(in,N,old,O,&p);
 assert(converted.error==EOPNOTSUPP&&converted.field==469);empty(p);
 assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 memcpy(in+512,address,6);memcpy(before,in,N);seed(p);
 converted=AssociationCompat::convert(in,N,old,O,&p);
 assert(converted.error==EOPNOTSUPP&&converted.field==469);empty(p);
 assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
}
static void flag_address_pairs(){
 uint8_t in[N],before[N],old[O],saved[O];NativeRequest p;
 init(in,false);memcpy(before,in,N);seed(p);
 assert(!PrivateMAC::parseNative(in,N,p).error);empty(p);assert(!memcmp(in,before,N));
 assert(!AssociationCompat::convert(in,N,old,O,&p).error);empty(p);
 // Address without policy flag is never used or silently dropped.
 for(size_t j=512;j<518;j++){
  init(in,false);in[j]=1;memcpy(before,in,N);memset(old,0x5c,O);memcpy(saved,old,O);seed(p);
  auto r=AssociationCompat::convert(in,N,old,O,&p);assert(r.error==EOPNOTSUPP&&r.field==j);
  empty(p);assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 }
 init(in);memset(in+512,0,6);seed(p);auto r=PrivateMAC::parseNative(in,N,p);
 assert(r.error==EINVAL&&r.field==512);empty(p);
 // Minimal valid caller-supplied private address is preserved byte-for-byte.
 in[512]=2;memcpy(before,in,N);assert(!PrivateMAC::parseNative(in,N,p).error);
 assert(p.requested&&!memcmp(p.address,in+512,6)&&!memcmp(in,before,N));
 // A caller with no consumer keeps the running Test005 refusal behavior.
 for(unsigned policy=0;policy<2;policy++){
  init(in,true,policy);memset(old,0x5c,O);memcpy(saved,old,O);memcpy(before,in,N);
  r=PrivateMAC::parseNative(in,N,p);assert(!r.error&&p.deviceTypeInDhcpAllowed==(policy!=0));
  auto c=AssociationCompat::convert(in,N,old,O);assert(c.error==EOPNOTSUPP&&c.field==468);
  assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 }
}
static void exact_plan_mapping(){
 // All remaining native flag bits are preserved in the legacy carrier.
 for(unsigned policy=0;policy<2;policy++)for(unsigned value=0;value<256;value++){
  if(value&0x40)continue; // Scope is a separately validated owned extension.
  if(policy&&!(value&8))continue; // No-private+policy is explicitly refused above.
  uint8_t in[N],before[N],old[O+32],expected[O]{};init(in,(value&8)!=0,policy);
  in[467]=(uint8_t)(255-value);in[468]=(uint8_t)value;memcpy(before,in,N);memset(old,0x5c,sizeof(old));
  NativeRequest p;seed(p);auto r=AssociationCompat::convert(in,N,old+16,O,&p);assert(!r.error);
  assert(p.requested==((value&8)!=0));
  assert(p.deviceTypeInDhcpAllowed==(policy!=0));
  if(p.requested)assert(!memcmp(p.address,in+512,6));else empty(p);
  memcpy(expected,in,6);ScanCompat::write16(expected+6,1);ScanCompat::write16(expected+8,8);
  memcpy(expected+12,in+16,496);expected[464]&=(uint8_t)~8U;expected[465]&=(uint8_t)~0x40U;
  assert(!memcmp(old+16,expected,O)&&!memcmp(before,in,N));
  assert(old[16+463]==(uint8_t)(255-value)&&old[16+464]==(uint8_t)(value&~8U));
  for(size_t j=0;j<16;j++)assert(old[j]==0x5c&&old[O+16+j]==0x5c);
 }
}
static void unknown_tails(){
 for(size_t field=518;field<N;field++)if(field!=899){
  uint8_t in[N],before[N],old[O],saved[O];init(in,true,true);in[field]=1;memcpy(before,in,N);
  memset(old,0x5c,O);memcpy(saved,old,O);NativeRequest p;seed(p);
  auto r=AssociationCompat::convert(in,N,old,O,&p);
  assert(r.error==EOPNOTSUPP&&r.field==field);empty(p);
  assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 }
 const uint8_t policies[]={0,3,255};for(auto policy:policies){
  uint8_t in[N],before[N],old[O],saved[O];init(in,true,true);in[899]=policy;memcpy(before,in,N);
  memset(old,0x5c,O);memcpy(saved,old,O);NativeRequest p;seed(p);
  auto r=AssociationCompat::convert(in,N,old,O,&p);assert(r.error&&r.field==899);empty(p);
  assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 }
}
static void bounds_and_early_failures(){
 uint8_t in[N],before[N],old[O],saved[O];init(in,true,true);memcpy(before,in,N);memset(old,0x5c,O);memcpy(saved,old,O);
 NativeRequest p;
 for(size_t length: {size_t(0),size_t(517),size_t(907),size_t(909)}){
  seed(p);assert(PrivateMAC::parseNative(in,length,p).error==EINVAL);empty(p);
  seed(p);assert(AssociationCompat::convert(in,length,old,O,&p).error==EINVAL);empty(p);
  assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 }
 seed(p);assert(PrivateMAC::parseNative(nullptr,N,p).error==EINVAL);empty(p);
 seed(p);assert(AssociationCompat::convert(nullptr,N,old,O,&p).error==EINVAL);empty(p);
 seed(p);assert(AssociationCompat::convert(in,N,nullptr,O,&p).error==EINVAL);empty(p);
 seed(p);assert(AssociationCompat::convert(in,N,old,O-1,&p).error==EINVAL);empty(p);
 seed(p);assert(AssociationCompat::convert(in,N,in,O,&p).error==EINVAL);empty(p);
 assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));
 // A failed unrelated header/security/policy field cannot retain a stale plan.
 const size_t fields[]={0,4,6,8,12,16,60,64,68,140,160,180,208,472,508};
 for(auto field:fields){init(in,true,true);in[field]=0xff;if(field==208)ScanCompat::write16(in+field,258);memcpy(before,in,N);seed(p);
  auto r=AssociationCompat::convert(in,N,old,O,&p);assert(r.error);empty(p);
  assert(!memcmp(in,before,N)&&!memcmp(old,saved,O));}
}
static void aliases_no_write(){
 // Placement-new gives aliased outputs their actual object lifetime. Snapshot
 // after construction: the function itself must not alter a single byte.
 const size_t offsets[]={0,512,901,907};
 for(auto offset:offsets){
  uint8_t storage[N+sizeof(NativeRequest)],before[N+sizeof(NativeRequest)],old[O],saved[O];init(storage,true,true);memset(storage+N,0x62,sizeof(NativeRequest));
  auto *alias=new(storage+offset) NativeRequest;memcpy(before,storage,sizeof(storage));
  memset(old,0x5c,O);memcpy(saved,old,O);
  assert(PrivateMAC::parseNative(storage,N,*alias).error==EINVAL);
  assert(!memcmp(storage,before,sizeof(storage)));
  assert(AssociationCompat::convert(storage,N,old,O,alias).error==EINVAL);
  assert(!memcmp(storage,before,sizeof(storage))&&!memcmp(old,saved,O));
 }
 for(size_t offset: {size_t(0),size_t(O-1)}){
  uint8_t in[N],before[N],storage[O+sizeof(NativeRequest)],saved[O+sizeof(NativeRequest)];init(in);memcpy(before,in,N);memset(storage,0x5c,sizeof(storage));
  auto *alias=new(storage+offset) NativeRequest;memcpy(saved,storage,sizeof(storage));
  assert(AssociationCompat::convert(in,N,storage,O,alias).error==EINVAL);
  assert(!memcmp(in,before,N)&&!memcmp(storage,saved,sizeof(storage)));
 }
}
int main(int argc,char **argv){assert(argc==2);switch(atoi(argv[1])){
 case 0:first_byte();break;case 1:unsupported_flags();break;case 2:flag_address_pairs();break;
 case 3:exact_plan_mapping();break;case 4:unknown_tails();break;case 5:bounds_and_early_failures();break;
 case 6:aliases_no_write();break;default:abort();}}
'''


class PrivateMACNativeRequestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="private-mac-native-", dir="/private/tmp")
        cls.binary = pathlib.Path(cls.tmp.name) / "test"
        r = subprocess.run(
            ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-I", str(PROJECT / "src/scan_kernel"),
             "-x", "c++", "-", "-o", str(cls.binary)],
            input=HARNESS, text=True, capture_output=True, timeout=60)
        if r.returncode:
            raise AssertionError(r.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def scenario(self, n):
        r = subprocess.run([str(self.binary), str(n)], capture_output=True, text=True, timeout=10)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_all_256_first_bytes_require_supplied_local_unicast(self): self.scenario(0)
    def test_every_unsupported_extension_byte_value_rejects_and_clears_plan(self): self.scenario(1)
    def test_policy_flag_and_address_must_agree_and_default_consumer_refuses(self): self.scenario(2)
    def test_exact_plan_address_legacy_private_bit_and_other_flags(self): self.scenario(3)
    def test_each_unknown_tail_preserves_input_and_old_and_clears_plan(self): self.scenario(4)
    def test_bounds_and_early_failures_never_keep_stale_plan(self): self.scenario(5)
    def test_aliased_outputs_are_rejected_without_any_write(self): self.scenario(6)


if __name__ == "__main__":
    unittest.main()
