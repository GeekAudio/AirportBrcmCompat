"""Host contracts for byte layouts proven from OCLP IO80211ElCap binaries."""
import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/request_abi.hpp"
#include "legacy_wifi_compat/scan_bridge.hpp"
#include "legacy_wifi_compat/association_bridge.hpp"
#include <assert.h>
#include <initializer_list>
#include <stdlib.h>

namespace R=LegacyWiFi::RequestABI;
namespace S=LegacyWiFi::ScanBridge;

static void put16(uint8_t *p,uint16_t x){memcpy(p,&x,2);}
static void put32(uint8_t *p,uint32_t x){memcpy(p,&x,4);}
static uint32_t get32(const uint8_t *p){uint32_t x;memcpy(&x,p,4);return x;}
static void initNative(uint8_t *p){memset(p,0x5a,ScanCompat::NativeSize);put32(p,1);put16(p+0x8a,32);}
static void initHeader(uint8_t *p,const uint8_t *ies,size_t n){
 memset(p,0,S::KernelHeaderSize);put32(p,1);p[0x22]=4;p[0x60]=8;
 put16(p+0x8a,(uint16_t)n);R::writeU64(p+0x90,(uintptr_t)ies);
}

static void requestLayouts(){
 uint8_t raw32[R::User32Size]{};memcpy(raw32,"en7",3);put32(raw32+0x10,11);put32(raw32+0x14,4);
 put32(raw32+0x18,0x1234);put32(raw32+0x1c,0x12345678);
 R::View v{};assert(R::decode(raw32,sizeof(raw32),false,v));
 assert(v.type==11&&v.value==4&&v.length==0x1234&&v.data==0x12345678&&!v.user64);
 uint8_t kernel[R::KernelSize];R::encodeKernel(v,kernel);
 assert(!memcmp(kernel,raw32,0x1c)&&get32(kernel+0x20)==0x12345678&&get32(kernel+0x24)==0);
 uint8_t raw64[R::User64Size]{};memcpy(raw64,"en8",3);put32(raw64+0x10,20);put32(raw64+0x14,2);
 put32(raw64+0x18,0x5678);put32(raw64+0x1c,0xdeadbeef);R::writeU64(raw64+0x20,0x123456789abcdef0ULL);
 assert(R::decode(raw64,sizeof(raw64),true,v));
 assert(v.type==20&&v.value==2&&v.length==0x5678&&v.data==0x123456789abcdef0ULL&&v.user64);
 R::encodeKernel(v,kernel);assert(!memcmp(kernel,raw64,0x1c));
 assert(R::readU64(kernel+0x20)==0x123456789abcdef0ULL);
 assert(!R::decode(raw64,sizeof(raw64)-1,true,v));assert(!R::decode(raw32,sizeof(raw32)+1,false,v));
 assert(!R::decode(nullptr,sizeof(raw32),false,v));
}

static void pureMaterializer(){
 uint8_t native[ScanCompat::NativeSize],before[ScanCompat::NativeSize];initNative(native);
 memcpy(before,native,sizeof(native));
 uint8_t header[S::KernelHeaderSize];uint8_t ies[5]={1,2,3,4,5};initHeader(header,ies,sizeof(ies));
 assert(!S::convertResult(native,sizeof(native),header,sizeof(header),ies,sizeof(ies)));
 assert(get32(native)==1&&ScanCompat::read16(native+0x8a)==5);
 assert(!memcmp(native+0x8c,ies,sizeof(ies)));
 for(size_t i=0;i<sizeof(native);i++){
  if(i<35||(i>=36&&i<129)||(i>=132&&i<137)||i==0x8a||i==0x8b)continue;
  if(i>=0x8c&&i<0x8c+ScanCompat::NativeIECapacity){
   assert(native[i]==(i<0x8c+sizeof(ies)?ies[i-0x8c]:0));continue;
  }
  assert(native[i]==before[i]);
 }
 uint8_t snapshot[sizeof(native)];memcpy(snapshot,native,sizeof(native));
 assert(S::convertResult(native,sizeof(native),header,sizeof(header)-1,ies,sizeof(ies))==EINVAL);
 assert(!memcmp(native,snapshot,sizeof(native)));
 assert(S::convertResult(native,sizeof(native),header,sizeof(header),ies,sizeof(ies)-1)==EINVAL);
 assert(!memcmp(native,snapshot,sizeof(native)));
 put16(header+0x8a,(uint16_t)(S::MaximumIEBytes+1));
 assert(S::convertResult(native,sizeof(native),header,sizeof(header),ies,sizeof(ies))==EOVERFLOW);
 assert(!memcmp(native,snapshot,sizeof(native)));
}

static uint8_t user[ScanCompat::NativeSize],ieData[16],result[S::KernelHeaderSize];
static unsigned originalCalls,allocations,frees,inCalls,outCalls,managerCalls,resultCalls;
static int resultError,copyError;
static bool mutateOnCopyOut;
static void *controller=(void*)0x100,*interface=(void*)0x200,*vif=(void*)0x300;
static int original(void *c,void *i,void *v,ScanCompat::Request *r,bool user64){
 assert(c==controller&&i==interface&&v==vif&&r&&user64);originalCalls++;return 71;
}
static void *allocate(size_t n){assert(n==sizeof(user));allocations++;return calloc(1,n);}
static void deallocate(void *p,size_t n){assert(n==sizeof(user));
 for(size_t i=0;i<n;i++)assert(!((uint8_t*)p)[i]);frees++;free(p);}
static int copyIn(void *c,uint64_t address,void *out,size_t n){
 assert(c==controller&&address==(uintptr_t)user&&n==sizeof(user));inCalls++;
 assert(resultCalls==managerCalls&&resultCalls>0); // Match ElCap get-result-before-copyIn order.
 if(copyError)return copyError;memcpy(out,user,n);return 0;
}
static int copyOut(void *c,const void *src,uint64_t address,size_t n){
 assert(c==controller&&address==(uintptr_t)user&&n==sizeof(user));outCalls++;
 memcpy(user,src,n);if(mutateOnCopyOut)memset(ieData,0,sizeof(ieData));return 0;
}
static void *manager(void *i){assert(i==interface);managerCalls++;return (void*)0x400;}
static int getResult(void *m,const uint8_t **out){assert(m==(void*)0x400);resultCalls++;
 if(resultError)return resultError;*out=result;return 0;
}
static void liveHandler(){
 memset(ieData,0x71,sizeof(ieData));initHeader(result,ieData,7);
 initNative(user);ScanCompat::Request req{};req.type=11;req.length=ScanCompat::NativeSize;req.userData=(uintptr_t)user;
 S::API api{original,allocate,deallocate,copyIn,copyOut,manager,getResult};
 mutateOnCopyOut=true;assert(!S::handle(api,controller,interface,vif,&req,true));
 assert(originalCalls==0&&allocations==frees&&inCalls==1&&outCalls==1&&managerCalls==1&&resultCalls==1);
 assert(ScanCompat::read16(user+0x8a)==7);
 for(size_t i=0;i<7;i++)assert(user[0x8c+i]==0x71);
 mutateOnCopyOut=false;
 req.length=ScanCompat::OldSize;assert(S::handle(api,controller,interface,vif,&req,true)==71);
 assert(originalCalls==1);
 req.length=ScanCompat::NativeSize;resultError=EBUSY;
 assert(S::handle(api,controller,interface,vif,&req,true)==EBUSY);
 assert(originalCalls==1&&outCalls==1);resultError=0;
 copyError=EFAULT;assert(S::handle(api,controller,interface,vif,&req,true)==EFAULT);
 assert(originalCalls==1&&outCalls==1);copyError=0;
 initHeader(result,ieData,S::MaximumIEBytes+1);
 assert(S::handle(api,controller,interface,vif,&req,true)==EOVERFLOW);
 assert(originalCalls==1&&outCalls==1);
}
static void initAssociation(uint8_t *p,bool secure){
 namespace A=LegacyWiFi::AssociationBridge;
 memset(p,0,A::NativePayloadSize);put32(p,1);put16(p+4,2);put32(p+8,1);
 put32(p+12,secure?8:0);put32(p+16,3);memcpy(p+20,"abc",3);put32(p+60,1);p[899]=2;
 if(secure){put32(p+64,32);put32(p+68,6);memset(p+76,0x39,32);}
}
static void associationNarrowing(){
 namespace A=LegacyWiFi::AssociationBridge;
 uint8_t native[A::NativePayloadSize],before[A::NativePayloadSize];
 uint8_t legacy[A::MaximumPayloadSize],legacyBefore[A::MaximumPayloadSize];
 for(bool secure:{false,true}){
  initAssociation(native,secure);memcpy(before,native,sizeof(native));memset(legacy,0x6d,sizeof(legacy));
  assert(!A::convert(native,sizeof(native),legacy,sizeof(legacy)).error);
  assert(!memcmp(native,before,sizeof(native))&&get32(legacy)==1);
  assert(ScanCompat::read16(legacy+4)==2&&ScanCompat::read16(legacy+6)==1);
 }
 initAssociation(native,true);put32(native+508,4);memcpy(before,native,sizeof(native));
 memset(legacy,0x6d,sizeof(legacy));memcpy(legacyBefore,legacy,sizeof(legacy));
 auto rejected=A::convert(native,sizeof(native),legacy,sizeof(legacy));
 assert(rejected.error==EOPNOTSUPP&&rejected.field==508);
 assert(!memcmp(native,before,sizeof(native))&&!memcmp(legacy,legacyBefore,sizeof(legacy)));
 initAssociation(native,true);put32(native+472,32);memset(native+476,0x11,32);
 assert(A::convert(native,sizeof(native),legacy,sizeof(legacy)).error==EOPNOTSUPP);
 assert(A::convert(native,sizeof(native),native,sizeof(native)).error==EINVAL);
 assert(A::convert(native,sizeof(native)-1,legacy,sizeof(legacy)).error==EINVAL);
}
namespace A=LegacyWiFi::AssociationBridge;
static uint8_t assocUser[A::NativePayloadSize],assocLegacy[A::MaximumPayloadSize];
static A::Registry assocRegistry;
static A::API *assocAPI=nullptr;
static unsigned assocOriginalCalls,assocInputCopies,assocConsumes;
static uintptr_t assocThread(){return 0x31;}
static void *assocAllocate(size_t size){assert(size==A::StorageSize);return calloc(1,size);}
static void assocDeallocate(void *p,size_t size){assert(size==A::StorageSize);
 for(size_t i=0;i<size;i++)assert(!((uint8_t*)p)[i]);free(p);}
static void assocLock(void *p){auto *locked=(bool*)p;assert(!*locked);*locked=true;}
static void assocUnlock(void *p){auto *locked=(bool*)p;assert(*locked);*locked=false;}
static int assocCopyIn(void *c,uint64_t source,void *destination,size_t size){
 assert(c==(void*)0x100);assocInputCopies++;
 if(size==A::NativePayloadSize){assert(source==(uintptr_t)assocUser);memcpy(destination,assocUser,size);return 0;}
 assert(size==A::MaximumPayloadSize);
 const int consumed=A::consumeCopyIn(*assocAPI,0x31,0x51,c,source,destination,size);
 if(consumed==0)assocConsumes++;
 return consumed==-1?EFAULT:consumed;
}
static int assocOriginal(void *c,void *i,void *v,ScanCompat::Request *r,bool user64){
 assert(c==(void*)0x100&&i==(void*)0x200&&v==nullptr&&user64&&r);
 assocOriginalCalls++;if(!assocRegistry.head)return 73;
 assert(r->length==A::MaximumPayloadSize);
 uint8_t rejected[A::MaximumPayloadSize];
 assert(assocRegistry.consume(0x31,0x52,c,r->userData,rejected,sizeof(rejected))==-1);
 assert(assocRegistry.consume(0x32,0x51,c,r->userData,rejected,sizeof(rejected))==-1);
 assert(assocRegistry.consume(0x31,0x51,(void*)0x999,r->userData,rejected,sizeof(rejected))==EINVAL);
 assert(assocRegistry.consume(0x31,0x51,c,r->userData+1,rejected,sizeof(rejected))==EINVAL);
 uint8_t local[A::MaximumPayloadSize];
 const int result=assocCopyIn(c,r->userData,local,sizeof(local));
 if(result)return result;
 assert(assocRegistry.consume(0x31,0x51,c,r->userData,local,sizeof(local))==EINVAL);
 memcpy(assocLegacy,local,sizeof(local));return 0;
}
static void associationHandler(){
 bool locked=false;assocRegistry.lock={&locked,assocLock,assocUnlock};
 A::API api{assocOriginal,assocCopyIn,assocAllocate,assocDeallocate,assocThread,&assocRegistry,0x51};
 assocAPI=&api;initAssociation(assocUser,true); // This fixture is a representable WPA2 key request.
 ScanCompat::Request request{};request.type=20;request.length=A::NativePayloadSize;
 request.userData=(uintptr_t)assocUser;
 A::Result validation;bool consumed=false;
 assert(!A::handle(api,(void*)0x100,(void*)0x200,nullptr,&request,true,&validation,&consumed));
 assert(validation.error==0&&consumed&&assocConsumes==1&&assocOriginalCalls==1);
 assert(request.length==A::NativePayloadSize&&!assocRegistry.head&&!locked);
 assert(!memcmp(assocLegacy,assocUser+0,4));
 const unsigned calls=assocOriginalCalls;
 request.length=0x1d0;assert(A::handle(api,(void*)0x100,(void*)0x200,nullptr,&request,true)==73);
 assert(assocOriginalCalls==calls+1);
 request.length=A::NativePayloadSize;
 initAssociation(assocUser,true);put32(assocUser+508,4);
 memset(assocLegacy,0x6d,sizeof(assocLegacy));uint8_t before[sizeof(assocLegacy)];memcpy(before,assocLegacy,sizeof(before));
 assert(A::handle(api,(void*)0x100,(void*)0x200,nullptr,&request,true,&validation,&consumed)==EOPNOTSUPP);
 assert(!consumed&&assocOriginalCalls==calls+1&&!memcmp(before,assocLegacy,sizeof(before)));
}
int main(){requestLayouts();pureMaterializer();liveHandler();associationNarrowing();associationHandler();}
'''


class LegacyBSDBridgeTests(unittest.TestCase):
    def test_request_and_scan_bridge_contracts(self):
        with tempfile.TemporaryDirectory(prefix="legacy-bsd-bridge-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "test.cpp"
            binary = pathlib.Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                            "-I", str(PROJECT / "src"), str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
