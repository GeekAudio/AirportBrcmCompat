"""Fictional buffers only; no password, OS network API or SAE handshake test."""
import pathlib
import subprocess
import tempfile
import unittest

import test_private_mac_association_flow as flow

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "association_compat.hpp"
#include <assert.h>
#include <string.h>
using namespace AssociationCompat;
static void put(uint8_t *p,uint32_t x){memcpy(p,&x,4);}
static void init(uint8_t *p,bool privateMac=false){
 memset(p,0,NativeSize);put(p,1);ScanCompat::write16(p+4,2);put(p+8,1);put(p+12,4096);
 put(p+16,3);memcpy(p+20,"abc",3);put(p+64,16);put(p+68,10);
 memset(p+76,0x5c,16);put(p+472,32);memset(p+476,0xa6,32);put(p+508,0x40000004U);p[899]=2;
 if(privateMac){p[468]=8;const uint8_t address[]={6,1,2,3,4,5};memcpy(p+512,address,6);}
}
int main(){
 for(uint32_t upper=0;upper<65536;upper++){
  const bool expected=upper==0||upper==8
#ifdef AIRPORT_BRCM_SAE_COMPAT
   ||upper==4096
#endif
   ;assert(PrivateMAC::supportedStationAuthUpper(upper)==expected);
 }
 uint8_t native[NativeSize],before[NativeSize],old[LegacySize],oldBefore[LegacySize];init(native);
#ifndef AIRPORT_BRCM_SAE_COMPAT
 auto denied=convert(native,NativeSize,old,LegacySize);assert(denied.error==EOPNOTSUPP&&denied.field==12);return 0;
#else
 for(uint32_t mask:{0U,4U,0x40000004U})for(unsigned length=8;length<=63;length++){
  init(native);put(native+508,mask);put(native+64,length);memset(native+76,0x6b,length);
  memcpy(before,native,NativeSize);assert(!convert(native,NativeSize,old,LegacySize).error);
  assert(ScanCompat::read16(old+8)==4096);assert(!memcmp(old+12,native+16,496));
  assert(ScanCompat::read32(old+504)==mask&&!memcmp(native,before,NativeSize));
 }
 // Every refused shape leaves caller's buffers unchanged. Never substitute
 // WPA2, discard a policy bit, or treat a raw PMK/PSK as an SAE password.
 const uint32_t invalid[][2]={{12,4097},{68,6},{64,0},{64,7},{64,64},{472,0},{472,31},{472,33},
                            {508,0x100},{508,0x40000100},{508,8},{508,0xffffffffU},{899,0}};
 for(auto &entry:invalid){init(native);put(native+entry[0],entry[1]);memcpy(before,native,NativeSize);
  memset(old,0x7d,LegacySize);memcpy(oldBefore,old,LegacySize);auto result=convert(native,NativeSize,old,LegacySize);
  assert(result.error&&!memcmp(native,before,NativeSize)&&!memcmp(old,oldBefore,LegacySize));}
 init(native,true);PrivateMAC::NativeRequest plan;assert(!convert(native,NativeSize,old,LegacySize,&plan).error&&plan.requested);
 Scope scope;scope.thread=1;scope.caller=2;scope.controller=(void*)3;scope.interface=(void*)4;scope.source=5;
 scope.legacy=old;scope.consumed=true;scope.privatePlan=plan;scope.authUpper=4096;
 {DriverValidationLease lease(scope);assert(lease.acquired());assert(infrastructureIntent(scope,1,(void*)3,(void*)4));
  ScanCompat::write16(old+8,8);assert(!infrastructureIntent(scope,1,(void*)3,(void*)4));}
 assert(!scope.driverValidated);
#endif
}
'''


class AssociationSaeTests(unittest.TestCase):
    def compile_run(self, source, enabled):
        with tempfile.TemporaryDirectory(prefix="sae-subset-", dir="/private/tmp") as tmp:
            cpp = pathlib.Path(tmp) / "test.cpp"
            binary = pathlib.Path(tmp) / "test"
            cpp.write_text(source)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-Wno-unused-variable", "-fsanitize=address,undefined", "-g",
                            *(["-DAIRPORT_BRCM_SAE_COMPAT=1"] if enabled else []),
                            "-include", "initializer_list", "-I", str(PROJECT / "src/scan_kernel"),
                            "-I", str(PROJECT / "src/private_mac_compat"), str(cpp), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_default_build_still_rejects_sae(self):
        self.compile_run(HARNESS, False)

    def test_default_build_rejects_compact_sae_without_writing_output(self):
        self.compile_run(r'''
#include "association_profiles.hpp"
#include <cassert>
#include <cstring>
int main(){
 uint8_t input[856]{},out[548],before[548];uint32_t version=1;uint16_t upper=4096,mode=2;
 memcpy(input,&version,4);memcpy(input+4,&mode,2);memcpy(input+8,&upper,2);
 memset(out,0x6d,sizeof(out));memcpy(before,out,sizeof(out));
 auto result=AssociationProfiles::convertSonoma14(input,sizeof(input),out,sizeof(out));
 assert(result.error==EOPNOTSUPP&&result.field==8&&!memcmp(out,before,sizeof(out)));
}
''', False)

    def test_candidate_preserves_selected_auth_carriers_policy_and_owned_intent(self):
        self.compile_run(HARNESS, True)

    def test_sae_password_subset_across_all_three_request_profiles(self):
        source = r'''
#include "association_compat.hpp"
#include <cassert>
#include <cstdlib>
#include <cstring>
using namespace AssociationCompat;
static uint8_t payload[NativeSize], before[NativeSize], received[LegacySize];
static Registry registry;
static bool locked;
static unsigned originals,copies,allocations;
static int originalError;
static size_t length;
static void put16(uint8_t*p,uint16_t v){memcpy(p,&v,2);}
static void put32(uint8_t*p,uint32_t v){memcpy(p,&v,4);}
static void lock(void*){assert(!locked);locked=true;}
static void unlock(void*){assert(locked);locked=false;}
static uintptr_t thread(){return 11;}
static bool primary(void*c,void*i,const char name[16]){
 return c==(void*)1 && i==(void*)2 && !memcmp(name,"en0",4);
}
static void*allocate(size_t n){assert(!locked&&n==StorageSize);++allocations;return malloc(n);}
static void release(void*p,size_t n){assert(!locked);for(size_t j=0;j<n;++j)assert(!((uint8_t*)p)[j]);free(p);}
static int copy(void*,uint64_t from,void*to,size_t n){
 assert(!locked&&from==(uintptr_t)payload&&n==length);++copies;memcpy(to,payload,n);return 0;
}
static int original(void*c,void*i,void*v,void*infra,ScanCompat::Request*r,bool user64){
 assert(!locked&&user64&&!v&&!infra&&c==(void*)1&&i==(void*)2);++originals;
 assert(registry.find(11,c,i));
 assert(!registry.consume(11,22,c,r->userData,received,LegacySize));
 return originalError;
}
static void init(size_t n,unsigned key,uint32_t allowed){
 memset(payload,0,sizeof(payload));length=n;put32(payload,1);put16(payload+4,2);
 const bool compact=n==AssociationProfiles::Sonoma14Size;
 if(compact){put16(payload+6,1);put16(payload+8,4096);}else{put32(payload+8,1);put32(payload+12,4096);}
 const size_t shift=compact?0:4;
 put32(payload+12+shift,3);memcpy(payload+16+shift,"abc",3);
 put32(payload+56+shift,1);put32(payload+60+shift,key);put32(payload+64+shift,10);
 memset(payload+72+shift,0x63,key);put32(payload+468+shift,32);
 memset(payload+472+shift,0xa7,32);put32(payload+504+shift,allowed);
 if(n==NativeSize)payload[899]=2;
 originals=copies=allocations=0;memcpy(before,payload,sizeof(payload));
}
static int run(){
 ScanCompat::Request request{};memcpy(request.interfaceName,"en0",4);
 request.type=20;request.length=length;request.userData=(uintptr_t)payload;
 API api{};api.original=original;api.copyIn=copy;api.allocate=allocate;api.deallocate=release;
 api.primaryInterface=primary;api.registry=&registry;api.caller=22;api.currentThread=thread;
 const int error=handle(api,(void*)1,(void*)2,nullptr,nullptr,&request,true);
 assert(!registry.head&&!locked&&!memcmp(payload,before,sizeof(payload)));
 return error;
}
int main(){
 registry.lock={&registry,lock,unlock};
 for(size_t n:{size_t(856),size_t(900),size_t(908)})for(uint32_t allowed:{0U,4U,0x40000004U})
  for(unsigned key=8;key<=63;++key){
   init(n,key,allowed);originalError=0;assert(!run()&&originals==1&&copies==1&&allocations==1);
   assert(ScanCompat::read16(received+8)==4096&&ScanCompat::read32(received+60)==key);
   assert(ScanCompat::read32(received+64)==10&&ScanCompat::read32(received+468)==32);
   assert(ScanCompat::read32(received+504)==allowed);
   const size_t shift=n==856?0:4;assert(!memcmp(received+72,payload+72+shift,key));
   assert(!memcmp(received+472,payload+472+shift,32));
   if(n==856)assert(!memcmp(received,payload,508));
   init(n,key,allowed);originalError=73;assert(run()==73&&originals==1);
  }
 for(unsigned key:{0,7,64}){init(856,key,4);assert(run()==EOPNOTSUPP&&!originals);}
 const unsigned offsets[]={6,8,64,468,504,508,855};
 const uint32_t values[]={0,4097,6,0,8,1,1};
 for(unsigned k=0;k<7;++k){init(856,16,4);
  if(offsets[k]==6||offsets[k]==8)put16(payload+offsets[k],values[k]);
  else if(offsets[k]==855)payload[855]=1;else put32(payload+offsets[k],values[k]);
  memcpy(before,payload,sizeof(payload));assert(run()==EOPNOTSUPP&&!originals);
 }
}
'''
        self.compile_run(source, True)

    def test_candidate_private_address_scope_and_error_paths(self):
        source = flow.HARNESS.replace("int main(", "int legacy_flow_main(", 1).replace('puts("ok");}', 'puts("ok");return 0;}')
        source += r'''
static void sae(Fixture &p){put32(p.payload+12,4096);put32(p.payload+64,16);put32(p.payload+68,10);
 put32(p.payload+472,32);put32(p.payload+508,0x40000004U);}
int main(){
 {Fixture p;sae(p);assert(!p.run()&&p.planApplied&&p.planCompleted&&p.copied);p.allPrivate();
  assert(p.observedSurvey.cipher68.low16==10&&p.observedSurvey.keyLength64.low16==16&&p.observedSurvey.pmkLength472.low16==32);}
 for(int error:{EINVAL,EIO,ETIMEDOUT}){Fixture p;sae(p);p.driverError=error;
  assert(p.run()==error&&p.planApplied&&p.planCompleted);p.allPrivate();}
 for(unsigned key:{0,7,64}){Fixture p;sae(p);put32(p.payload+64,key);assert(p.run()==EOPNOTSUPP&&!p.setters&&!p.drivers);}
}
'''
        self.compile_run(source, True)


if __name__ == "__main__":
    unittest.main()
