"""Exercise the actual restricted GET12 adapter, including original copy semantics."""
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
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"cap contract line %d\n",__LINE__); exit(2); } } while(0)
static unsigned originals,ins,outs;
static int mode,originalReturn;
static uint8_t bytes[32],snapshot[32];
static Request *expectedRequest;
static void *expectedController,*expectedInterface,*expectedVirtual,*expectedInfra;
static bool expectedKernel;
static char expectedBSDName[16]="en1";
static int original(void *c,void *i,void *v,void *a,Request *r,bool k) {
    CHECK(c==expectedController && i==expectedInterface && v==expectedVirtual && a==expectedInfra);
    CHECK(r==expectedRequest && k==expectedKernel); originals++;
    if(originalReturn)return originalReturn;
    CHECK(r && r->userData==reinterpret_cast<uint64_t>(bytes+4));
    for(unsigned n=0;n<12;n++)bytes[n+4]=(uint8_t)(n*3+1);
    bytes[9]=mode==4?0x48:0x88;
    r->length=mode==7?6:12;
    if(mode==8)r->userData++;
    return 0;
}
static int in(void *,uint64_t address,void *out,size_t n) {
    CHECK(n==12 && address==reinterpret_cast<uint64_t>(bytes+4) && originals==1);ins++;
    if(mode==5)return EFAULT;memcpy(out,bytes+4,n);return 0;
}
static int out(void *,const void *in,uint64_t address,size_t n) {
    CHECK(n==12 && address==reinterpret_cast<uint64_t>(bytes+4) && ins==1);outs++;
    for(unsigned x=0;x<n;x++)CHECK(static_cast<const uint8_t*>(in)[x]==(x==5?0xc8:bytes[x+4]));
    if(mode==6)return EFAULT;memcpy(bytes+4,in,n);return 0;
}
static bool primary(void *c,void *i,const char name[16]) {
    return c==expectedController && i==expectedInterface &&
        PrimaryInterface::sameRequestAndProperty(name,expectedBSDName,strlen(expectedBSDName));
}
int main(int argc,char **argv) {
    CHECK(argc==2);mode=atoi(argv[1]);memset(bytes,0x35,sizeof(bytes));
    Request r{};memcpy(r.interfaceName,"en1",4);r.type=12;r.length=21;r.userData=reinterpret_cast<uint64_t>(bytes+4);
    void *controller=reinterpret_cast<void*>(1),*interface=reinterpret_cast<void*>(2),*vif=nullptr,*infra=nullptr;
    Request *arg=&r;bool kernel=mode==3,changed=true;
    int expected=0;originalReturn=0;bool eligible=true;
    switch(mode) {
    case 1:case 3:case 4:break;
    case 2:originalReturn=EBUSY;expected=EBUSY;break;
    case 5:case 6:expected=EFAULT;break;
    case 7:case 8:eligible=false;break;
    case 9:r.length=12;break;
    case 10:r.length=4;break;
    case 11:memcpy(r.interfaceName,"awdl0",6);break;
    case 12:vif=reinterpret_cast<void*>(3);break;
    case 13:r.value=1;break;
    case 14:r.padding=1;break;
    case 15:r.type=11;break;
    case 16:r.userData=0;break;
    case 17:arg=nullptr;break;
    case 18:controller=nullptr;break;
    case 19:interface=nullptr;break;
    case 20:r.interfaceName[8]=1;break;
    case 21:interface=nullptr;infra=reinterpret_cast<void*>(4);break;
    case 22:memcpy(r.interfaceName,"en0",4);memcpy(expectedBSDName,"en0",4);break;
    case 23:memcpy(r.interfaceName,"en7",4);memcpy(expectedBSDName,"en7",4);break;
    case 24:r.length=16;break;
    case 25:r.length=16;memcpy(expectedBSDName,"en0",4);eligible=false;originalReturn=77;expected=77;break;
    case 26:r.length=19;break;
    case 27:r.length=20;eligible=false;originalReturn=77;expected=77;break;
    default:return 64;
    }
    if(mode>=9 && mode<=21) { eligible=false; originalReturn=77; expected=77; }
    expectedRequest=arg;expectedController=controller;expectedInterface=interface;
    expectedVirtual=vif;expectedInfra=infra;expectedKernel=kernel;
    memcpy(snapshot,bytes,sizeof(bytes));
    API api{};api.copyIn=in;api.copyOut=out;api.primaryInterface=primary;
    CHECK(handleCapabilities(api,original,controller,interface,vif,infra,arg,kernel,&changed)==expected);
    CHECK(originals==1);
    if(!eligible || mode==2)CHECK(ins==0 && outs==0 && !changed);
    else if(mode==5)CHECK(ins==1 && outs==0 && !changed);
    else if(mode==4)CHECK(ins==1 && outs==0 && !changed);
    else if(mode==6)CHECK(ins==1 && outs==1 && !changed);
    else CHECK(ins==1 && outs==1 && changed && bytes[9]==0xc8);
    if(originalReturn)CHECK(!memcmp(bytes,snapshot,sizeof(bytes)));
    for(unsigned n=0;n<sizeof(bytes);n++)if(n<4 || n>=16)CHECK(bytes[n]==0x35);
    if(mode!=8)CHECK(r.userData==((mode==16)?0:reinterpret_cast<uint64_t>(bytes+4)));
    return 0;
}
'''

@unittest.skipUnless(shutil.which('clang++'),'C++ compiler required')
class CapabilityContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp=tempfile.TemporaryDirectory(prefix='kernel-cap-contract-')
        cls.binary=pathlib.Path(cls.tmp.name)/'contract'
        r=subprocess.run(['clang++','-std=c++14','-Wall','-Wextra','-Werror','-I',str(PROJECT/'src/scan_kernel'),'-x','c++','-','-o',str(cls.binary)],input=HARNESS,text=True,capture_output=True,timeout=30)
        if r.returncode:raise AssertionError(r.stderr)
    @classmethod
    def tearDownClass(cls):cls.tmp.cleanup()
    def cases(self,values):
        for value in values:
            with self.subTest(case=value):
                r=subprocess.run([str(self.binary),str(value)],capture_output=True,text=True,timeout=5)
                self.assertEqual(r.returncode,0,r.stderr)
    def test_native_advertisement_and_already_set_bit(self):self.cases((1,3,4,22,23,24,26))
    def test_sonoma_length_requires_primary_interface_identity(self):self.cases((25,))
    def test_original_and_copy_errors_preserve_failure(self):self.cases((2,5,6))
    def test_unexpected_reply_does_not_advertise(self):self.cases((7,8))
    def test_old_awdl_and_unrelated_requests_pass_through(self):self.cases(range(9,22))
    def test_unknown_native_capacity_is_not_inferred(self):self.cases((27,))

if __name__=='__main__':unittest.main()
