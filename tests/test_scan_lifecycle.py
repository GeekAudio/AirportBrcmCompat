#!/usr/bin/env python3
"""Offline lifecycle tests. All kernel/IOKit/Lilu entry points are mocks."""
from pathlib import Path
import subprocess
import tempfile
import unittest
PROJECT = Path(__file__).resolve().parents[1]
src = (PROJECT / 'src/scan_kernel/lifecycle.cpp').read_text()
diag = (PROJECT / 'src/scan_kernel/diagnostics.hpp').read_text()
identity = (PROJECT / 'src/scan_kernel/kernel_identity.hpp').read_text()
src='\n'.join(line for line in src.splitlines() if not line.startswith('#include '))
preamble=r'''
#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <map>
#include <string>
#include <mutex>
#include <cstdio>
#include <cassert>
#define PRODUCT_NAME SkywalkScanCompat
#define MODULE_VERSION 0.1.1
#define LILU_CUSTOM_KMOD_INIT 1
#define LILU_CUSTOM_IOKIT_INIT 1
#define EXPORT
#define CAT_(a,b) a##b
#define CAT(a,b) CAT_(a,b)
#define ADDPR(a) CAT(SkywalkScanCompat_,a)
#define STR_(a) #a
#define xStringify(a) STR_(a)
#define SYSLOG(...) ((void)0)
#define OSDeclareDefaultStructors(X) public: X()=default; ~X() override=default;
#define OSDefineMetaClassAndStructors(X,Y)
using SInt32=int32_t;
using kern_return_t=int;
struct kmod_info_t {};
constexpr int KERN_SUCCESS=0,KERN_FAILURE=5;
struct OSObject { int refs=1; virtual ~OSObject()=default; void retain(){++refs;} void release(){if(!--refs)delete this;} };
struct OSBoolean:OSObject { bool value; explicit OSBoolean(bool b):value(b){refs=100000;} };
OSBoolean trueValue(true),falseValue(false);
OSObject *kOSBooleanTrue=&trueValue,*kOSBooleanFalse=&falseValue;
struct OSNumber:OSObject { uint32_t value; explicit OSNumber(uint32_t v):value(v){} static OSNumber *withNumber(uint64_t v,unsigned){return new OSNumber(v);} };
struct OSString:OSObject { std::string value; explicit OSString(const char *s):value(s){} };
struct OSDictionary:OSObject {
 std::map<std::string,OSObject*> entries;
 static OSDictionary *withCapacity(unsigned){return new OSDictionary;}
 bool setObject(const char *key,OSObject *value){value->retain();auto &p=entries[key];if(p)p->release();p=value;return true;}
 ~OSDictionary(){for(auto &p:entries)p.second->release();}
};
bool parentStart=true, failLock=false, failSet=false;
struct IOService:OSDictionary {
 unsigned propertyWrites=0, registrations=0;
 virtual IOService *probe(IOService*,SInt32*){return this;}
 virtual bool start(IOService*){return parentStart;}
 virtual void stop(IOService*){}
 bool setProperty(const char *key,const char *value){auto *s=new OSString(value);bool ok=setProperty(key,s);s->release();return ok;}
 bool setProperty(const char *key,OSObject *value){++propertyWrites;if(failSet){failSet=false;return false;}return setObject(key,value);}
 void registerService(){++registrations;}
};
using IOLock=std::mutex;
IOLock *IOLockAlloc(){return failLock?nullptr:new IOLock;}
void IOLockLock(IOLock *l){l->lock();} void IOLockUnlock(IOLock *l){l->unlock();} void IOLockFree(IOLock *l){delete l;}
bool lilu_get_boot_args(const char*,void*,size_t){return false;} bool checkKernelArgument(const char*){return false;}
enum class KernelVersion {Tahoe=25};
struct PluginConfiguration {const char *product;size_t version;uint32_t runmode;const char **disableArg;size_t disableArgNum;const char **debugArg;size_t debugArgNum;const char **betaArg;size_t betaArgNum;KernelVersion minKernel,maxKernel;void(*pluginStart)();};
struct LiluAPI {
 enum class Error {NoError,LockError,MemoryError,UnsupportedFeature,IncompatibleOS,Disabled,TooLate,Offline};
 Error accessResult=Error::NoError,loadResult=Error::NoError;
 unsigned accessCalls=0,loadCalls=0,releaseCalls=0;
 Error requestAccess(){++accessCalls;return accessResult;}
 template<class... T> Error shouldLoad(T...){++loadCalls;return loadResult;}
 Error releaseAccess(){++releaseCalls;return Error::NoError;}
} lilu;
'''
identity_mock=r'''
namespace ScanKernelIdentity {
Profile mockState=Profile::Pending;
Profile currentProfile(){return mockState;}
}
'''
post=r'''
unsigned pluginCalls=0;
void init(){++pluginCalls;ScanDiagnostics::record(ScanDiagnostics::BuildGuard,0);}
PluginConfiguration ADDPR(config)={"SkywalkScanCompat",11,1,nullptr,0,nullptr,0,nullptr,0,KernelVersion::Tahoe,KernelVersion::Tahoe,init};
OSDictionary *snapshot(SkywalkScanCompat &s){return dynamic_cast<OSDictionary*>(s.entries.at("ScanCompatDiagnostics"));}
uint32_t value(OSDictionary *d,const char *k){return dynamic_cast<OSNumber*>(d->entries.at(k))->value;}
int code(OSDictionary *d,const char *k){return static_cast<int32_t>(value(dynamic_cast<OSDictionary*>(d->entries.at(k)),"Code"));}
bool boolean(OSDictionary *d,const char *k){return dynamic_cast<OSBoolean*>(d->entries.at(k))->value;}
int main(int argc,char **argv){
 assert(argc==2);std::string mode=argv[1];
 if(mode=="late"||mode=="nostart")lilu.accessResult=LiluAPI::Error::TooLate;
 if(mode=="offline")lilu.accessResult=LiluAPI::Error::Offline;
 if(mode=="disabled")lilu.loadResult=LiluAPI::Error::Disabled;
 if(mode=="memory")failLock=true;
 assert(ADDPR(kern_start)(nullptr,nullptr)==KERN_SUCCESS);
 assert(lilu.accessCalls==1);
 if(mode=="late"||mode=="offline"||mode=="nostart"){
  assert(lilu.loadCalls==0&&lilu.releaseCalls==0&&pluginCalls==0&&!ADDPR(startSuccess));
 }else{
  assert(lilu.loadCalls==1&&lilu.releaseCalls==1);
  assert(pluginCalls==unsigned(mode!="disabled"&&mode!="memory"));
 }
 if(mode=="nostart") {assert(ADDPR(kern_stop)(nullptr,nullptr)==KERN_SUCCESS);puts("nostart: pass");return 0;}
 if(mode=="registered") {assert(ADDPR(kern_stop)(nullptr,nullptr)==KERN_FAILURE);puts("registered: pass");return 0;}
 SkywalkScanCompat s;SInt32 score=0;
 assert(s.probe(nullptr,&score)==&s);
 if(mode=="memory") {assert(!s.start(nullptr));assert(ADDPR(kern_stop)(nullptr,nullptr)==KERN_SUCCESS);puts("memory: pass");return 0;}
 assert(s.start(nullptr)&&s.registrations==1);
 auto *d=snapshot(s);
 assert(value(d,"AutomaticCompatibility")==1);
 assert(value(d,"KernelImageState")==static_cast<uint32_t>(ScanKernelIdentity::Profile::Pending));
 ScanKernelIdentity::mockState=ScanKernelIdentity::Profile::Structural;
 ScanDiagnostics::record(ScanDiagnostics::Guards,0);
 d=snapshot(s);
 assert(value(d,"KernelImageState")==static_cast<uint32_t>(ScanKernelIdentity::Profile::Structural));
 assert(code(d,"Bootstrap")==0&&boolean(d,"ObserverActive"));
 assert(code(d,"RuntimeBuild")==-1);
 for(int runtimeCode:{1,2,3,0}){
  unsigned prior=s.propertyWrites;
  ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,runtimeCode);
  assert(s.propertyWrites==prior+1&&code(snapshot(s),"RuntimeBuild")==runtimeCode);
  assert(boolean(dynamic_cast<OSDictionary*>(snapshot(s)->entries.at("RuntimeBuild")),"Reached"));
  ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,runtimeCode);
  assert(s.propertyWrites==prior+1);
 }
 d=snapshot(s);
 assert(dynamic_cast<OSString*>(s.entries.at("VersionInfo"))->value=="0.1.1");
 if(mode=="late"||mode=="offline"){
  assert(code(d,"Access")==int(lilu.accessResult)&&code(d,"ShouldLoad")==-1);
  assert(!boolean(d,"PluginInitEntered"));
 }else if(mode=="disabled"){
  assert(code(d,"ShouldLoad")==5&&!boolean(d,"BootstrapAccepted"));
 }else{
  assert(boolean(d,"BootstrapAccepted")&&boolean(d,"PluginInitEntered")&&boolean(d,"PluginInitReturned"));
  assert(code(d,"BuildGuard")==0);
 }
 unsigned writes=s.propertyWrites;
 ScanDiagnostics::record(ScanDiagnostics::FirstConverted,0);
 assert(s.propertyWrites==writes+1);writes=s.propertyWrites;
 ScanDiagnostics::record(ScanDiagnostics::FirstConverted,0);
 ScanDiagnostics::record(static_cast<ScanDiagnostics::Stage>(-1),0);
 ScanDiagnostics::record(ScanDiagnostics::StageCount,0);
 assert(s.propertyWrites==writes);
 const ScanDiagnostics::Entry batch[]={{ScanDiagnostics::AllowedAuthLow16,4},
   {ScanDiagnostics::AllowedAuthHigh16,0x4000},{ScanDiagnostics::ColocatedScopeLengthLow16,36}};
 ScanDiagnostics::recordBatch(batch,3);
 assert(s.propertyWrites==writes+1);writes=s.propertyWrites;
 assert(code(snapshot(s),"AllowedAuthLow16")==4&&code(snapshot(s),"AllowedAuthHigh16")==0x4000);
 ScanDiagnostics::recordBatch(batch,3);assert(s.propertyWrites==writes);
 const ScanDiagnostics::Entry invalid[]={{ScanDiagnostics::AllowedAuthLow16,8},{ScanDiagnostics::StageCount,0}};
 ScanDiagnostics::recordBatch(invalid,2);ScanDiagnostics::recordBatch(nullptr,3);
 ScanDiagnostics::recordBatch(batch,0);ScanDiagnostics::recordBatch(batch,ScanDiagnostics::StageCount+1);
 assert(s.propertyWrites==writes&&code(snapshot(s),"AllowedAuthLow16")==4);
 failSet=true;
 ScanDiagnostics::symbolMask(0xff);
 assert(s.propertyWrites==writes+1);
 ScanDiagnostics::publish();
 assert(s.propertyWrites==writes+2&&value(snapshot(s),"SymbolMask")==63);
 assert(ADDPR(kern_stop)(nullptr,nullptr)==KERN_FAILURE);
 s.stop(nullptr);writes=s.propertyWrites;
 ScanDiagnostics::record(ScanDiagnostics::FirstPending,0);
 assert(s.propertyWrites==writes&&s.refs==1);
 assert(ADDPR(kern_stop)(nullptr,nullptr)==KERN_FAILURE);
 printf("%s: pass\n",mode.c_str());
}
'''
class LifecycleOfflineTests(unittest.TestCase):
    """Compile the actual lifecycle source against mocks; never load a kext.

    No real Lilu, IOKit, IORegistry or hardware calls are linked. Each scenario
    runs in a fresh process so static lifecycle state starts with its sentinels.
    """
    @classmethod
    def setUpClass(cls):
        cls.work = tempfile.TemporaryDirectory(prefix='skyscan-lifecycle-offline-', dir='/private/tmp')
        cls.source = Path(cls.work.name) / 'lifecycle_mock.cpp'
        cls.binary = Path(cls.work.name) / 'lifecycle_mock'
        cls.source.write_text(preamble + '\n' + identity + '\n' + identity_mock + '\n' + diag + '\n' + src + '\n' + post)
        compiled = subprocess.run(['xcrun', 'clang++', '-std=c++14', '-Wall', '-Wextra', '-Werror',
                                   '-Wno-unused-parameter', str(cls.source), '-o', str(cls.binary)],
                                  capture_output=True, text=True, timeout=30)
        if compiled.returncode:
            cls.work.cleanup()
            raise AssertionError(compiled.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, name):
        result = subprocess.run([str(self.binary), name], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(name + ': pass', result.stdout)

    def test_success_and_snapshot_boundaries(self): self.scenario('success')
    def test_too_late_observer_remains_visible(self): self.scenario('late')
    def test_offline_observer_remains_visible(self): self.scenario('offline')
    def test_shouldload_rejection_releases_access(self): self.scenario('disabled')
    def test_failed_bootstrap_before_observer_can_stop(self): self.scenario('nostart')
    def test_entered_plugin_without_observer_cannot_stop(self): self.scenario('registered')
    def test_lock_allocation_failure_registers_no_hooks(self): self.scenario('memory')


if __name__ == '__main__':
    unittest.main()
