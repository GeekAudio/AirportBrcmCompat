"""Run the actual nonblocking kernel handler logic with fake copy/manager APIs."""
import pathlib
import shutil
import subprocess
import tempfile
import unittest

PROJECT=pathlib.Path(__file__).resolve().parents[1]
HARNESS=r'''
#include <stdio.h>
#include <stdlib.h>
#include "scan_compat.hpp"
using namespace ScanCompat;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"contract line %d\n",__LINE__); exit(2); } } while(0)
static uint8_t user[NativeSize],before[NativeSize],old[OldSize],oldBefore[OldSize];
static unsigned allocations,frees,inCalls,outCalls,managerCalls,resultCalls,originalCalls;
static int mode;
static void put32(void *p,uint32_t x) { memcpy(p,&x,4); }
static int original(void *c,void *i,void *v,void *a,Request *r,bool k) {
    (void)c;(void)i;(void)v;(void)a;(void)r;(void)k;originalCalls++; return 77;
}
static void *alloc(size_t n) { CHECK(n==NativeSize); allocations++; return mode==6?nullptr:calloc(1,n); }
static void release(void *p,size_t n) {
    CHECK(n==NativeSize);for(size_t i=0;i<n;i++)CHECK(static_cast<uint8_t*>(p)[i]==0);
    frees++;free(p);
}
static int copyIn(void *,uint64_t address,void *dest,size_t n) {
    CHECK(address==reinterpret_cast<uint64_t>(user) && n==NativeSize);inCalls++;
    if(mode==7)return EFAULT;memcpy(dest,user,n);return 0;
}
static int copyOut(void *,const void *src,uint64_t address,size_t n) {
    CHECK(address==reinterpret_cast<uint64_t>(user) && n==NativeSize);outCalls++;
    if(mode==18)return EFAULT;
    if(mode==30)memset(old,0,OldSize); // Manager lifetime ends after snapshot, not saved.
    memcpy(user,src,n);return 0;
}
static void *manager(void *) { managerCalls++;return mode==10?nullptr:reinterpret_cast<void*>(2); }
static int get(void *mgr,const uint8_t **ptr) {
    CHECK(mgr==reinterpret_cast<void*>(2));resultCalls++;
    if(mode==11)return EBUSY;if(mode==12)return EIO;if(mode==28)return EINVAL;
    *ptr=mode==13?nullptr:old;return 0;
}
static bool primary(void *c,void *i,const char name[16]) {
    PrimaryInterface::Name parsed;
    return c==reinterpret_cast<void*>(1) && i==reinterpret_cast<void*>(3) &&
        PrimaryInterface::parseRequestName(name,parsed) && parsed.unit==1;
}
int main(int argc,char **argv) {
    CHECK(argc==2);mode=atoi(argv[1]);
    for(size_t i=0;i<NativeSize;i++)user[i]=(uint8_t)(i*7+3);
    memset(old,0x5a,OldSize);put32(user,1);put32(old,1);
    old[0x22]=15;old[0x60]=32;write16(user+0x8a,2048);write16(old+0x8a,1024);
    Request request{};request.type=11;request.value=-3;request.padding=0x12345678;
    memcpy(request.interfaceName,"en1",4);
    request.length=NativeSize;request.userData=reinterpret_cast<uint64_t>(user);
    Request *argument=&request;
    void *controller=reinterpret_cast<void*>(1),*interface=reinterpret_cast<void*>(3),*infra=nullptr;
    int expected=0;
    switch(mode) {
    case 1:case 29:case 30:break;
    case 2:request.length=OldSize;expected=77;break;
    case 3:request.type=48;expected=77;break;
    case 4:argument=nullptr;expected=77;break;
    case 5:interface=nullptr;expected=77;break;
    case 6:expected=ENOMEM;break;
    case 7:expected=EFAULT;break;
    case 8:put32(user,2);expected=EINVAL;break;
    case 9:write16(user+0x8a,2049);expected=EINVAL;break;
    case 10:expected=ENXIO;break;
    case 11:expected=EBUSY;break;
    case 12:case 13:expected=EIO;break;
    case 14:put32(old,2);expected=EOVERFLOW;break;
    case 15:old[0x22]=16;expected=EOVERFLOW;break;
    case 16:old[0x60]=33;expected=EOVERFLOW;break;
    case 17:write16(old+0x8a,1025);expected=EOVERFLOW;break;
    case 18:expected=EFAULT;break;
    case 19:write16(user+0x8a,0);break;
    case 20:write16(user+0x8a,1);break;
    case 21:write16(old+0x8a,0);break;
    case 22: // Direct conversion invalid lengths must not touch output.
      memcpy(before,user,NativeSize);CHECK(convert(user,NativeSize-1,old,OldSize)==EINVAL);
      CHECK(!memcmp(before,user,NativeSize));return 0;
    case 23:request.length=OldSize;expected=77;break;
    case 24:request.userData=0;expected=EINVAL;break;
    case 25:controller=nullptr;expected=EINVAL;break;
    case 26:interface=nullptr;infra=reinterpret_cast<void*>(4);expected=77;break;
    case 27:break;
    case 28:expected=EINVAL;break;
    default:return 64;
    }
    memcpy(before,user,NativeSize);memcpy(oldBefore,old,OldSize);Request requestBefore=request;
    API api{original,alloc,release,copyIn,copyOut,manager,get,primary};
    CHECK(handle(api,controller,interface,nullptr,infra,argument,mode==23)==expected);
    CHECK(!memcmp(&request,&requestBefore,sizeof(request)));
    CHECK(allocations==frees+(mode==6));
    if(expected==77)CHECK(originalCalls==1 && allocations==0 && managerCalls==0);
    else CHECK(originalCalls==0);
    if(mode==7 || mode==8 || mode==9)CHECK(managerCalls==0 && resultCalls==0);
    if(expected!=0)CHECK(!memcmp(user,before,NativeSize));
    else {
        CHECK(outCalls==1 && inCalls==1 && managerCalls==1 && resultCalls==1);
        uint16_t expectedIE=read16(oldBefore+0x8a)<read16(before+0x8a)?read16(oldBefore+0x8a):read16(before+0x8a);
        CHECK(read16(user+0x8a)==expectedIE);
        for(size_t i=0;i<IEOffset;i++) {
            if(i==138 || i==139)continue;
            bool field=i<35 || (i>=36 && i<129) || (i>=132 && i<137);
            CHECK(user[i]==(field?oldBefore[i]:before[i]));
        }
        for(size_t i=0;i<NativeIECapacity;i++)CHECK(user[IEOffset+i]==(i<expectedIE?oldBefore[IEOffset+i]:0));
        CHECK(!memcmp(user+0x88c,before+0x88c,0x54));
    }
    return 0;
}
'''

@unittest.skipUnless(shutil.which('clang++'),'C++ compiler required')
class KernelScanContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='kernel-scan-contract-')
        cls.binary=pathlib.Path(cls.tmp.name)/'contract'
        r=subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror','-I',str(PROJECT/'src/scan_kernel'),
                          '-x','c++','-','-o',str(cls.binary)],input=HARNESS,text=True,capture_output=True,timeout=30)
        if r.returncode:raise AssertionError(r.stderr)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def cases(self,values):
        for value in values:
            with self.subTest(case=value):
                r=subprocess.run([str(self.binary),str(value)],capture_output=True,text=True,timeout=5)
                self.assertEqual(r.returncode,0,r.stderr)
    def test_native_fields_bounds_tail_and_capacities(self):self.cases((1,19,20,21,26,27))
    def test_old_and_unrelated_contexts_pass_through(self):self.cases((2,3,4,5,23))
    def test_allocation_copy_and_manager_errors_free_buffer(self):self.cases((6,7,10,18,24,25))
    def test_invalid_user_input_does_not_consume_scan_cursor(self):self.cases((8,9,22))
    def test_pending_eof_and_driver_errors_are_not_retried(self):self.cases((11,12,13,28))
    def test_bad_legacy_fields_never_reach_copyout(self):self.cases((14,15,16,17))
    def test_private_data_zeroed_and_no_pointer_saved_after_snapshot(self):self.cases((29,30))

if __name__=='__main__':unittest.main()
