"""Bounded GET11 conversion for the independently sampled native result shapes."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "scan_kernel/scan_compat.hpp"
#include <cassert>
#include <cstdlib>
#include <vector>
using namespace ScanCompat;
static void put32(void *p,uint32_t x){memcpy(p,&x,4);}
static void oldResult(uint8_t *p,size_t count) {
    memset(p,0,OldSize);put32(p,1);p[0x22]=7;p[0x60]=3;
    write16(p+0x8a,count);
    for(size_t i=0;i<OldIECapacity;++i)p[IEOffset+i]=static_cast<uint8_t>(i*7+1);
}
static void resultBounds(size_t size,size_t capacity) {
    std::vector<uint8_t> storage(size+32,0x91),old(OldSize);
    auto *native=storage.data()+16;memset(native,0x5a,size);
    put32(native,1);write16(native+0x8a,capacity);oldResult(old.data(),OldIECapacity);
    auto before=storage;
    assert(convert(native,size,old.data(),old.size())==0);
    assert(read16(native+0x8a)==OldIECapacity);
    assert(!memcmp(native+IEOffset,old.data()+IEOffset,OldIECapacity));
    for(size_t i=OldIECapacity;i<capacity;++i)assert(native[IEOffset+i]==0);
    // Scan-identifier/other native fields after the IE array belong to the
    // user envelope and must not be overwritten by old padding or memset.
    assert(!memcmp(native+IEOffset+capacity,before.data()+16+IEOffset+capacity,
                   size-IEOffset-capacity));
    assert(!memcmp(storage.data(),before.data(),16));
    assert(!memcmp(storage.data()+size+16,before.data()+size+16,16));
    before=storage;
    write16(native+0x8a,capacity+1);before=storage;
    assert(convert(native,size,old.data(),old.size())==EINVAL);
    assert(storage==before);
    write16(native+0x8a,capacity);oldResult(old.data(),OldIECapacity+1);before=storage;
    assert(convert(native,size,old.data(),old.size())==EOVERFLOW);
    assert(storage==before);
    assert(convert(native,size-1,old.data(),old.size())==EINVAL);
    assert(storage==before);
}
static std::vector<uint8_t> user,old;
static size_t expectedSize,allocated,freed,ins,outs,originals,resultCalls;
static bool identity=true;
static void *alloc(size_t n){assert(n==expectedSize);++allocated;return calloc(1,n);}
static void dealloc(void *p,size_t n){assert(n==expectedSize);++freed;
    for(size_t i=0;i<n;++i)assert(static_cast<uint8_t *>(p)[i]==0);free(p);}
static int in(void *,uint64_t source,void *dest,size_t n){
    assert(source==reinterpret_cast<uintptr_t>(user.data())&&n==expectedSize);
    ++ins;memcpy(dest,user.data(),n);return 0;}
static int out(void *,const void *source,uint64_t dest,size_t n){
    assert(dest==reinterpret_cast<uintptr_t>(user.data())&&n==expectedSize);
    ++outs;memcpy(user.data(),source,n);return 0;}
static void *manager(void *c){return c;}
static int result(void *,const uint8_t **p){++resultCalls;*p=old.data();return 0;}
static int original(void *,void *,void *,void *,Request *,bool){++originals;return 73;}
static bool matchesPrimary(void *,void *,const char *){return identity;}
static void handleSize(size_t size,size_t capacity) {
    expectedSize=size;user.assign(size,0);old.assign(OldSize,0);oldResult(old.data(),9);
    put32(user.data(),1);write16(user.data()+0x8a,capacity);
    memset(user.data()+IEOffset+capacity,0x6c,size-IEOffset-capacity);
    Request request{};memcpy(request.interfaceName,"en0",4);request.type=11;
    request.length=size;request.userData=reinterpret_cast<uintptr_t>(user.data());
    API api{original,alloc,dealloc,in,out,manager,result,matchesPrimary};
    auto before=user;const size_t oldCopies=outs;
    assert(handle(api,&api,&request,nullptr,nullptr,&request,true)==0);
    assert(outs==oldCopies+1&&allocated==freed);
    assert(request.length==size&&read16(user.data()+0x8a)==9);
    assert(!memcmp(user.data()+IEOffset+capacity,before.data()+IEOffset+capacity,
                   size-IEOffset-capacity));
    const size_t allocBefore=allocated,getBefore=resultCalls,copyBefore=ins;
    identity=false;
    assert(handle(api,&api,&request,nullptr,nullptr,&request,true)==73);
    identity=true;request.length=size-1;
    assert(handle(api,&api,&request,nullptr,nullptr,&request,true)==73);
    assert(allocated==allocBefore&&resultCalls==getBefore&&ins==copyBefore);
}
int main(){
    assert(CompactNativeSize==1228&&WideNativeSize==2264&&NativeSize==2272);
    resultBounds(CompactNativeSize,1024);resultBounds(WideNativeSize,2048);resultBounds(NativeSize,2048);
    handleSize(CompactNativeSize,1024);handleSize(WideNativeSize,2048);handleSize(NativeSize,2048);
    assert(originals==6);
}
'''


class ScanResultProfilesTests(unittest.TestCase):
    def test_all_sizes_preserve_tail_and_route_only_matching_requests(self):
        with tempfile.TemporaryDirectory(prefix='scan-result-profiles-') as directory:
            binary = Path(directory) / 'check'
            build = subprocess.run(
                ['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                 '-fsanitize=address,undefined', '-I', str(ROOT / 'src'),
                 '-x', 'c++', '-', '-o', str(binary)],
                input=HARNESS, text=True, capture_output=True, timeout=60)
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], capture_output=True, text=True, timeout=20)
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)


if __name__ == '__main__':
    unittest.main()
