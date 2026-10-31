import pathlib
import subprocess
import tempfile
import unittest

PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "scan_multiple_compat.hpp"
#include <assert.h>
#include <stdlib.h>
#include <mutex>
#include <thread>
#include <utility>
#include <initializer_list>
#include <atomic>
using namespace ScanMultipleCompat;
static void put32(uint8_t *p,uint32_t x) {memcpy(p,&x,4);}
static void init(uint8_t *p) {
 memset(p,0,NativeSize);put32(p,1);put32(p+4,3);put32(p+8,2);
 put32(p+12,1);put32(p+16,32);memset(p+20,0xa3,32);
 put32(p+0x19c,16);memset(p+0x1a0,0xb4,16*6);
 put32(p+0x200,1);put32(p+0x204,1);put32(p+0x208,31);put32(p+0x20c,47);
 put32(p+0x210,400);
 for(size_t j=0;j<400;j++){put32(p+0x214+j*12,1);put32(p+0x218+j*12,149);put32(p+0x21c+j*12,4);}
 memset(p+0x14d4,0x35,12); // Preserve common padding and full 64-bit flags.
}
static void conversion() {
 uint8_t in[NativeSize],snapshot[NativeSize],out[LegacySize+32],before[sizeof(out)];
 init(in);memcpy(snapshot,in,sizeof(in));memset(out,0x6d,sizeof(out));
 assert(!convert(in,NativeSize,out+16,LegacySize).error);
 assert(!memcmp(in,snapshot,NativeSize)&&!memcmp(out+16,in,LegacySize));
 for(size_t j=0;j<16;j++)assert(out[j]==0x6d&&out[LegacySize+16+j]==0x6d);
 // No failure may partially modify the destination or caller's input.
 for(size_t offset=LegacySize;offset<NativeSize;offset++) {
  init(in);in[offset]=1;memset(out,0x6d,sizeof(out));memcpy(before,out,sizeof(out));
  auto r=convert(in,NativeSize,out+16,LegacySize);assert(r.error==EOPNOTSUPP&&r.field==LegacySize);
  assert(!memcmp(out,before,sizeof(out)));
 }
 for(auto pair:{std::pair<size_t,uint32_t>(0,2),{8,11},{0x19c,17},{0x210,401},{0x10,33},{0x38,33}}) {
  init(in);put32(in+pair.first,pair.second);memset(out,0x6d,sizeof(out));memcpy(before,out,sizeof(out));
  assert(convert(in,NativeSize,out+16,LegacySize).error==EINVAL);assert(!memcmp(out,before,sizeof(out)));
 }
 init(in);assert(convert(in,NativeSize,in,LegacySize).error==EINVAL);
 assert(convert(in,NativeSize-1,out,LegacySize).error==EINVAL);
 assert(convert(in,NativeSize,out,LegacySize-1).error==EINVAL);
 assert(convert(nullptr,NativeSize,out,LegacySize).error==EINVAL);
}
static std::mutex mutex;
static void enter(void *p) {static_cast<std::mutex*>(p)->lock();}
static void leave(void *p) {static_cast<std::mutex*>(p)->unlock();}
static Registry registry {};
static thread_local uintptr_t owner=1;
static uintptr_t threadToken(){return owner;}
static unsigned allocations,frees,copies,originals;
static int allocationFail,copyError,driverError,mode;
static void *controller=(void*)0x123,*interface=(void*)0x456;
static constexpr uintptr_t caller=0x86fde;
static void *allocate(size_t n){assert(n==StorageSize);allocations++;return allocationFail?nullptr:calloc(1,n);}
static void deallocate(void *p,size_t n){assert(n==StorageSize);for(size_t j=0;j<n;j++)assert(!((uint8_t*)p)[j]);frees++;free(p);}
static int copy(void *c,uint64_t p,void *out,size_t n){assert(c==controller&&n==NativeSize);copies++;if(copyError)return copyError;memcpy(out,(void*)(uintptr_t)p,n);return 0;}
static bool primary(void *c,void *i,const char name[16]) {
 return c==controller&&i==interface&&PrimaryInterface::sameRequestAndProperty(name,"en1",3);
}
static API api;
static int original(void *c,void *i,void *v,void *infra,ScanCompat::Request *r,bool u) {
 originals++;assert(mutex.try_lock());mutex.unlock();
 if(mode==1)return EBUSY; // Original PID/busy rejection before copy remains intact.
 if(mode==2)return 0; // No copied prefix must not become success.
 if(mode==3){const auto length=r->length;r->length=NativeSize;const auto calls=originals;
  assert(handle(api,c,i,v,infra,r,u)==EBUSY&&originals==calls);r->length=length;}
 assert(r->length==LegacySize);uint8_t old[LegacySize];
 assert(registry.consume(owner,caller+1,c,r->userData,old,LegacySize)==-1);
 assert(registry.consume(owner+1,caller,c,r->userData,old,LegacySize)==-1);
 assert(registry.consume(owner,caller,(void*)0x999,r->userData,old,LegacySize)==EINVAL);
 assert(registry.consume(owner,caller,c,r->userData+1,old,LegacySize)==EINVAL);
 assert(registry.consume(owner,caller,c,r->userData,old,LegacySize-1)==EINVAL);
 assert(!registry.consume(owner,caller,c,r->userData,old,LegacySize));
 assert(!memcmp(old,(void*)(uintptr_t)r->userData,LegacySize));
 assert(registry.consume(owner,caller,c,r->userData,old,LegacySize)==EINVAL);
 return driverError;
}
static void lifecycle() {
 assert(registry.prepare({&mutex,enter,leave}));
 assert(!registry.prepare({&mutex,enter,leave}));
 api.original=original;api.copyIn=copy;api.allocate=allocate;api.deallocate=deallocate;
 api.currentThread=threadToken;api.registry=&registry;api.caller=caller;
 api.primaryInterface=primary;
 uint8_t data[NativeSize];init(data);ScanCompat::Request r {};memcpy(r.interfaceName,"en1",4);
 r.type=86;r.length=NativeSize;r.userData=(uintptr_t)data;
 auto before=r;Result validation;bool consumed=false;
 for(int e:{0,EINVAL,EBUSY,ENXIO,EIO}) {
  driverError=e;assert(handle(api,controller,interface,nullptr,nullptr,&r,true,&validation,&consumed)==e);
  assert(consumed&&validation.error==0&&!memcmp(&r,&before,sizeof(r))&&!registry.head);
 }
 mode=1;assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EBUSY);assert(!memcmp(&r,&before,sizeof(r))&&!registry.head);
 mode=2;assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EIO);assert(!memcmp(&r,&before,sizeof(r))&&!registry.head);
 mode=3;driverError=0;assert(!handle(api,controller,interface,nullptr,nullptr,&r,true));assert(!memcmp(&r,&before,sizeof(r))&&!registry.head);
 mode=0;copyError=EFAULT;auto calls=originals;
 assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EFAULT&&originals==calls);copyError=0;
 allocationFail=1;assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==ENOMEM&&originals==calls);allocationFail=0;
 data[LegacySize]=1;assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EOPNOTSUPP&&originals==calls);data[LegacySize]=0;
 // Old-size/32-bit/other-interface requests pass straight to original; a
 // test original that never consumes them provides an unambiguous witness.
 mode=1;r.length=LegacySize;calls=originals;assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EBUSY&&originals==calls+1);
 r=before;assert(handle(api,controller,interface,nullptr,nullptr,&r,false)==EBUSY);
 r.interfaceName[2]='2';assert(handle(api,controller,interface,nullptr,nullptr,&r,true)==EBUSY);r=before;
 assert(allocations==frees+1); // The explicit allocation failure owns no buffer.
}
static void ownership() {
 uint8_t bytes[LegacySize]={},out[LegacySize];Scope first;
 first.thread=1;first.caller=caller;first.controller=controller;first.source=1;first.legacy=bytes;
 assert(registry.add(first));Scope duplicate=first;assert(!registry.add(duplicate));
 assert(registry.consume(1,caller,controller,1,bytes,LegacySize)==EINVAL);
 std::thread other([&]{Scope second=first;second.thread=2;assert(registry.add(second));
  assert(!registry.consume(2,caller,controller,1,out,LegacySize));registry.remove(second);});other.join();
 assert(!first.consumed);assert(!registry.consume(1,caller,controller,1,out,LegacySize));
 registry.remove(first);assert(!registry.head);assert(registry.consume(1,caller,controller,1,out,LegacySize)==-1);
}
static void publication() {
 Registry fresh;std::mutex lock;uint8_t out[LegacySize];std::atomic<bool> go{false};
 assert(fresh.consume(1,caller,controller,1,out,LegacySize)==-1);
 std::thread reader([&]{while(!go.load(std::memory_order_acquire)){}
  for(unsigned j=0;j<10000;j++)assert(fresh.consume(1,caller,controller,1,out,LegacySize)==-1);});
 go.store(true,std::memory_order_release);assert(fresh.prepare({&lock,enter,leave}));reader.join();
 assert(fresh.ready());
}
int main(){conversion();lifecycle();ownership();publication();}
'''


class ScanMultipleTests(unittest.TestCase):
    def test_boundaries_ownership_and_original_errors(self):
        with tempfile.TemporaryDirectory(prefix="scan-multiple-test-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "test.cpp"
            binary = pathlib.Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                            "-I", str(PROJECT / "src/scan_kernel"), str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)

    def test_registry_publication_has_no_thread_sanitizer_race(self):
        with tempfile.TemporaryDirectory(prefix="scan-multiple-tsan-", dir="/private/tmp") as tmp:
            source = pathlib.Path(tmp) / "test.cpp"
            binary = pathlib.Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=thread", "-g", "-I", str(PROJECT / "src/scan_kernel"),
                            str(source), "-o", str(binary)], check=True)
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
