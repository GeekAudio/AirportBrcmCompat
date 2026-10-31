"""Old-provider authentication projection must preserve the chosen protocol."""
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/association_bridge.hpp"
#include <assert.h>
#include <initializer_list>
namespace A=LegacyWiFi::AssociationBridge;
void put16(uint8_t*p,uint16_t v){memcpy(p,&v,2);}
void put32(uint8_t*p,uint32_t v){memcpy(p,&v,4);}
void init(uint8_t*p){
 memset(p,0,A::ProjectedPayloadSize);put32(p,1);put16(p+4,2);
 put16(p+6,1);put16(p+8,8);put32(p+12,3);memcpy(p+16,"net",3);
 put32(p+56,1);put32(p+60,32);put32(p+64,6);
 for(unsigned j=0;j<32;j++)p[72+j]=p[472+j]=static_cast<uint8_t>(j+1);
 put32(p+468,32);put32(p+504,4);
 const uint8_t rsn[]={0x30,20,1,0,0,15,172,4,1,0,0,15,172,4,1,0,0,15,172,2,0,0};
 put16(p+204,sizeof(rsn));memcpy(p+206,rsn,sizeof(rsn));
}
int main(){
 uint8_t p[A::ProjectedPayloadSize],before[sizeof(p)],out[A::MaximumPayloadSize];
 init(p);memcpy(before,p,sizeof(p));memset(out,0x5a,sizeof(out));
 assert(!A::narrowProjected(p,sizeof(p),out,sizeof(out)).error);
 assert(!memcmp(out,p,sizeof(out))&&!memcmp(p,before,sizeof(p)));
 // Absent capabilities, present capabilities, and an explicitly empty PMKID
 // list preserve exactly the same single CCMP/PSK selection. Every accepted
 // capability combination is retained byte-for-byte (MFPR remains rejected).
 for(unsigned length: {20U,22U,24U}){
  for(unsigned caps=0;caps<65536;caps++){
   init(p);put16(p+204,length);p[207]=static_cast<uint8_t>(length-2);
   put16(p+226,length>=22?caps:0);put16(p+228,0);
   memcpy(before,p,sizeof(p));memset(out,0x5a,sizeof(out));
   const auto result=A::narrowProjected(p,sizeof(p),out,sizeof(out));
   if(length>=22&&(caps&0x40)){
    assert(result.error==EOPNOTSUPP);for(auto v:out)assert(v==0x5a);
   }else{
    assert(!result.error);assert(!memcmp(out,p,sizeof(out)));
   }
   assert(!memcmp(before,p,sizeof(p)));
  }
 }
 // Never erase PMKIDs or a cipher tail to fit the old provider. A count
 // without enough bytes is rejected too, rather than reading past the IE.
 for(unsigned count=1;count<65536;count++){
  init(p);put16(p+204,24);p[207]=22;put16(p+228,count);
  memset(out,0x5a,sizeof(out));
  assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error==EOPNOTSUPP);
  for(auto v:out)assert(v==0x5a);
 }
 for(unsigned length=0;length<=257;length++){
  if(length==20||length==22||length==24)continue;
  init(p);put16(p+204,length);p[207]=static_cast<uint8_t>(length>=2?length-2:0);
  memset(out,0x5a,sizeof(out));
  assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error==EOPNOTSUPP);
  for(auto v:out)assert(v==0x5a);
 }
 // Modern-to-old conversion uses the same validation and preserves the IE.
 init(p);put16(p+204,24);p[207]=22;
 uint8_t native[A::NativePayloadSize]{};
 put32(native,1);put32(native+4,ScanCompat::read16(p+4));
 put32(native+8,ScanCompat::read16(p+6));put32(native+12,ScanCompat::read16(p+8));
 memcpy(native+16,p+12,496);
 native[899]=2;
 memset(out,0x5a,sizeof(out));
 assert(!A::convert(native,sizeof(native),out,sizeof(out)).error);
 assert(!memcmp(out,p,sizeof(out)));
 // Every bit of either copy of the PMK matters. Disagreeing secrets must not
 // be silently resolved in favour of one of the two request fields.
 for(unsigned byte=0;byte<32;byte++)for(unsigned bit=0;bit<8;bit++){
  init(p);p[472+byte]^=1U<<bit;memset(out,0x5a,sizeof(out));
  assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error==EOPNOTSUPP);
  for(auto v:out)assert(v==0x5a);
 }
 // All algorithms and selectors are retained, never downgraded.
 const size_t fields[]={6,8,60,64,204,206,207,208,210,214,216,220,222,226,464,465,466,467,468,504,507,508,547};
 for(auto offset:fields){init(p);p[offset]^=0x40;memset(out,0x5a,sizeof(out));
  assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error);
  for(auto v:out)assert(v==0x5a);
 }
 // A producer with no PMK extension is accepted only if its unused bytes are zero.
 init(p);put32(p+468,0);memset(p+472,0,32);
 assert(!A::narrowProjected(p,sizeof(p),out,sizeof(out)).error);
 p[503]=1;assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error);
 init(p);put32(p+504,0x40000004U);
 assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error==EOPNOTSUPP);
 init(p);p[226]=0x40; // MFPR, though the chosen AKM is still PSK.
 assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)).error==EOPNOTSUPP);
 init(p);assert(A::narrowProjected(p,sizeof(p),p,sizeof(out)).error==EINVAL);
 assert(A::narrowProjected(p,sizeof(p)-1,out,sizeof(out)).error==EINVAL);
 assert(A::narrowProjected(p,sizeof(p),out,sizeof(out)-1).error==EINVAL);
}
'''


class LegacyAssociationPolicyTests(unittest.TestCase):
    def test_authentication_mapping(self):
        with tempfile.TemporaryDirectory(prefix="brcm-old-auth-") as tmp:
            source = pathlib.Path(tmp) / "policy.cpp"
            binary = pathlib.Path(tmp) / "policy"
            source.write_text(HARNESS)
            subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-I", str(ROOT / "src"),
                            str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)
