"""Real component with fake port/refcount KPIs; no real port, IOUC or mapping.

The SDK test only compiles an unlinked kernel object. Host scenarios execute
the actual .cpp with ASan/UBSan, not a reimplementation of its state machine.
"""
from pathlib import Path
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]

MOCK = r'''
#pragma once
#include <cstdint>
#include <cstddef>
#include <cassert>
using IOReturn=int32_t;
using io_user_reference_t=uint64_t;
using mach_port_t=void *;
using OSAsyncReference64=uint64_t[8];
enum {kOSAsyncRef64Count=8};
static constexpr mach_port_t MACH_PORT_NULL=nullptr;
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnBusy=2,
      kIOReturnNotReady=3,kIOReturnNotOpen=4,kIOReturnInternalError=5,
      kIOReturnAborted=6};
class IOWorkLoop;
class OSObject {public:virtual ~OSObject()=default;};
struct IOExternalMethodArguments {
    uint32_t version=2,selector=2;
    mach_port_t asyncWakePort=nullptr;
    uint64_t *asyncReference=nullptr;
    uint32_t asyncReferenceCount=0;
    const uint64_t *scalarInput=nullptr;uint32_t scalarInputCount=0;
    const void *structureInput=nullptr;uint32_t structureInputSize=0;
    void *structureInputDescriptor=nullptr;
    uint64_t *scalarOutput=nullptr;uint32_t scalarOutputCount=0;
    void *structureOutput=nullptr;uint32_t structureOutputSize=0;
    void *structureOutputDescriptor=nullptr;uint32_t structureOutputDescriptorSize=0;
    void *structureVariableOutputData=nullptr;
};
struct Control {
    static bool interrupt,interruptsEnabled;
    static int gateDepth,sendCalls,releaseCalls,migCleanupCalls,rights;
    static int clientRetains,clientReleases,loopRetains,loopReleases;
    static IOReturn sendResult,releaseResult;
    static uint64_t expected[8],lastSent[8],lastReleased[8];
    static void (*onSend)();static void (*onRelease)();
    static void reset();
};
class IOWorkLoop:public OSObject {
    unsigned gateDepth_=0;
public:
    int refs=1;
    using Action=IOReturn(*)(OSObject *,void *,void *,void *,void *);
    bool inGate() const {return gateDepth_!=0;}
    void retain() {++refs;++Control::loopRetains;}
    void release() {assert(!inGate() && refs>1);--refs;++Control::loopReleases;}
    IOReturn runAction(Action f,OSObject *owner,void *a=nullptr,void *b=nullptr,
                       void *c=nullptr,void *d=nullptr) {
        ++gateDepth_;++Control::gateDepth;const auto result=f(owner,a,b,c,d);
        --Control::gateDepth;--gateDepth_;
        return result;
    }
};
class IOUserClient:public OSObject {
protected:
    static IOReturn sendAsyncResult64(OSAsyncReference64,IOReturn,uint64_t *,uint32_t);
public:
    IOWorkLoop *loop;bool inactive=false;int refs=1;
    explicit IOUserClient(IOWorkLoop *value):loop(value){}
    void retain(){++refs;++Control::clientRetains;}
    void release(){assert(!loop->inGate() && refs>1);--refs;++Control::clientReleases;}
    bool isInactive() const{return inactive;}
    IOWorkLoop *getWorkLoop() const{return loop;}
    static IOReturn releaseAsyncReference64(OSAsyncReference64);
};
inline bool ml_at_interrupt_context(){return Control::interrupt;}
inline bool ml_get_interrupts_enabled(){return Control::interruptsEnabled;}
'''

HARNESS = r'''
#include "async_notification_owner.hpp"
#include <cstring>
#include <cstdlib>
#include <initializer_list>
using namespace AWDLKernel;
bool Control::interrupt=false;bool Control::interruptsEnabled=true;
int Control::gateDepth=0;int Control::sendCalls=0;int Control::releaseCalls=0;
int Control::migCleanupCalls=0;int Control::rights=0;
int Control::clientRetains=0;int Control::clientReleases=0;
int Control::loopRetains=0;int Control::loopReleases=0;
IOReturn Control::sendResult=0;IOReturn Control::releaseResult=0;
uint64_t Control::expected[8]={},Control::lastSent[8]={},Control::lastReleased[8]={};
void (*Control::onSend)()=nullptr;void (*Control::onRelease)()=nullptr;
void Control::reset(){
    assert(!rights && !gateDepth);
    interrupt=false;interruptsEnabled=true;
    sendCalls=releaseCalls=migCleanupCalls=0;
    clientRetains=clientReleases=loopRetains=loopReleases=0;
    sendResult=releaseResult=0;onSend=onRelease=nullptr;
    memset(lastSent,0,sizeof(lastSent));memset(lastReleased,0,sizeof(lastReleased));
    expected[0]=0x1111222233334441ULL;
    for(unsigned i=1;i<8;++i)expected[i]=0x8877665500001100ULL+i;
}
IOReturn IOUserClient::sendAsyncResult64(OSAsyncReference64 r,IOReturn result,
                                       uint64_t *args,uint32_t count){
    assert(!Control::gateDepth && !Control::interrupt && Control::interruptsEnabled);
    assert(Control::rights==1 && result==0 && !args && !count);
    assert((r[0]&~3ULL)==(Control::expected[0]&~3ULL));
    assert(!memcmp(r+1,Control::expected+1,7*sizeof(uint64_t)));
    memcpy(Control::lastSent,r,64);++Control::sendCalls;
    if(Control::onSend)Control::onSend();
    if(Control::sendResult)r[0]|=2; // Actual KPI's private logged-error flag.
    return Control::sendResult;
}
IOReturn IOUserClient::releaseAsyncReference64(OSAsyncReference64 r){
    assert(!Control::gateDepth && Control::rights==1);
    assert((r[0]&~3ULL)==(Control::expected[0]&~3ULL));
    assert(!memcmp(r+1,Control::expected+1,7*sizeof(uint64_t)));
    memcpy(Control::lastReleased,r,64);++Control::releaseCalls;
    if(Control::onRelease)Control::onRelease();
    --Control::rights;return Control::releaseResult; // Does not clear the array.
}
struct Fixture {
    IOWorkLoop loop;IOUserClient client{&loop};AsyncNotificationOwner owner;
    AsyncNotificationOwner::Context context{&client,&loop,7};
    IOExternalMethodArguments args{};uint64_t refs[8]{};
    Fixture(){
        Control::reset();memcpy(refs,Control::expected,64);
        args.asyncWakePort=reinterpret_cast<void *>(uintptr_t(refs[0]&~3ULL));
        args.asyncReference=refs;args.asyncReferenceCount=8;
        // Legal zero-length pointers remain nonnull, including poison pointers.
        args.scalarInput=reinterpret_cast<const uint64_t *>(uintptr_t(1));
        args.scalarOutput=reinterpret_cast<uint64_t *>(UINTPTR_MAX);
        args.structureInput=reinterpret_cast<const void *>(uintptr_t(1));
        args.structureOutput=reinterpret_cast<void *>(UINTPTR_MAX);
    }
    static IOReturn adoptAction(OSObject *,void *p,void *,void *,void *){
        auto &s=*static_cast<Fixture *>(p);
        return s.owner.adoptFromSuccessfulDispatch(s.context,s.args);
    }
    IOReturn rpc(){
        ++Control::rights;const auto r=loop.runAction(adoptAction,&client,this);
        // Host model of actual kobject error-request cleanup, not real IPC.
        if(r){--Control::rights;++Control::migCleanupCalls;}
        return r;
    }
    static IOReturn snapshotAction(OSObject *,void *p,void *out,void *,void *){
        auto &s=*static_cast<Fixture *>(p);
        return s.owner.snapshotInGate(s.context,
            *static_cast<AsyncNotificationOwner::Snapshot *>(out));
    }
    AsyncNotificationOwner::Snapshot snapshot(){
        AsyncNotificationOwner::Snapshot out;
        assert(loop.runAction(snapshotAction,&client,this,&out)==0);return out;
    }
    void closed(){
        assert(owner.close(context)==0);assert(owner.close(context)==0);
        assert(!Control::rights && client.refs==1 && loop.refs==1);
        assert(snapshot().state==AsyncNotificationOwner::State::Closed);
    }
};
static void success(){
    Fixture f;assert(f.rpc()==0);assert(Control::rights==1);
    assert(f.client.refs==2 && f.loop.refs==2);
    assert(f.owner.notifyZeroArgs(f.context)==0);
    assert(Control::sendCalls==1 && Control::releaseCalls==0 && Control::rights==1);
    auto s=f.snapshot();assert(s.inFlight==0 && s.adopted==1 && s.notifyAttempts==1);
    assert(s.notifySucceeded==1 && !s.notifyFailed && s.lastSend==0);
    f.closed();assert(Control::releaseCalls==1 && Control::migCleanupCalls==0);
    assert(f.snapshot().releaseAttempts==1);
    assert(f.owner.notifyZeroArgs(f.context)!=0 && Control::sendCalls==1);
    assert(f.rpc()!=0 && Control::rights==0 && Control::releaseCalls==1);
}
static void malformed(){
    for(unsigned field=0;field<17;++field){
        Fixture f;
        switch(field){
            case 0:f.args.version=1;break;case 1:f.args.selector=5;break;
            case 2:f.args.scalarInputCount=1;break;case 3:f.args.scalarOutputCount=1;break;
            case 4:f.args.structureInputSize=1;break;case 5:f.args.structureOutputSize=1;break;
            case 6:f.args.structureInputDescriptor=&f;break;
            case 7:f.args.structureOutputDescriptor=&f;break;
            case 8:f.args.structureOutputDescriptorSize=1;break;
            case 9:f.args.structureVariableOutputData=&f;break;
            case 10:f.args.asyncReferenceCount=7;break;
            case 11:f.args.asyncReferenceCount=9;break;
            case 12:f.args.asyncReference=nullptr;break;
            case 13:f.args.asyncWakePort=nullptr;break;
            case 14:f.refs[0]^=1;break; // Wrong ABI flag.
            case 15:f.refs[0]|=2;break; // Not a fresh incoming MIG reference.
            case 16:f.args.asyncWakePort=reinterpret_cast<void *>(uintptr_t(0x123));break;
        }
        assert(f.rpc()!=0 && Control::rights==0 && Control::migCleanupCalls==1);
        assert(Control::releaseCalls==0 && f.client.refs==1 && f.loop.refs==1);
        assert(f.snapshot().state==AsyncNotificationOwner::State::Empty);
        // Rejection neither adopts nor destroys the owner; a later valid call works.
        memcpy(f.refs,Control::expected,64);f.args={};f.args.asyncReference=f.refs;
        f.args.asyncReferenceCount=8;
        f.args.asyncWakePort=reinterpret_cast<void *>(uintptr_t(f.refs[0]&~3ULL));
        assert(f.rpc()==0);f.closed();assert(Control::releaseCalls==1);
    }
}
static void duplicateAndGeneration(){
    Fixture f;assert(f.rpc()==0);assert(f.rpc()==kIOReturnBusy);
    assert(Control::rights==1 && Control::migCleanupCalls==1 && !Control::releaseCalls);
    auto wrong=f.context;wrong.generation++;
    assert(f.owner.close(wrong)!=0 && Control::rights==1);
    assert(f.owner.notifyZeroArgs(wrong)!=0 && Control::sendCalls==0);
    IOUserClient other{&f.loop};wrong=f.context;wrong.client=&other;
    assert(f.owner.close(wrong)!=0 && Control::rights==1 && other.refs==1);
    f.closed();
}
static Fixture *current=nullptr;
static void duringSend(){
    auto &f=*current;
    assert(f.client.refs==3 && f.loop.refs==3);
    assert(f.snapshot().inFlight==1);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnBusy);
    assert(f.owner.close(f.context)==kIOReturnBusy);
    auto s=f.snapshot();assert(s.state==AsyncNotificationOwner::State::Closing && s.inFlight==1);
    assert(Control::rights==1 && !Control::releaseCalls);
    f.client.inactive=true; // Draining must still complete after inactivity.
}
static void inFlightClose(){
    Fixture f;assert(f.rpc()==0);current=&f;Control::onSend=duringSend;
    assert(f.owner.notifyZeroArgs(f.context)==0);Control::onSend=nullptr;current=nullptr;
    assert(f.snapshot().inFlight==0 && Control::sendCalls==1);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnNotOpen);
    f.closed();assert(Control::releaseCalls==1);
}
static void duringRelease(){
    auto &f=*current;
    assert(f.snapshot().state==AsyncNotificationOwner::State::Retiring);
    assert(f.owner.close(f.context)==kIOReturnBusy);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnNotOpen);
}
static void retiringClose(){
    Fixture f;assert(f.rpc()==0);current=&f;Control::onRelease=duringRelease;
    f.closed();Control::onRelease=nullptr;current=nullptr;
    assert(Control::releaseCalls==1 && f.snapshot().releaseAttempts==1);
}
static void sendErrors(){
    Fixture f;assert(f.rpc()==0);Control::sendResult=kIOReturnAborted;
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnAborted);
    assert(Control::rights==1 && Control::releaseCalls==0);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnAborted);
    assert((Control::lastSent[0]&2)!=0); // Only logged-error bit propagated.
    auto s=f.snapshot();assert(s.notifyAttempts==2 && s.notifyFailed==2 && !s.notifySucceeded);
    assert(s.lastSend==kIOReturnAborted);f.closed();
}
static void releaseError(){
    Fixture f;assert(f.rpc()==0);Control::releaseResult=kIOReturnAborted;
    assert(f.owner.close(f.context)==kIOReturnAborted);
    assert(f.owner.close(f.context)==kIOReturnAborted);
    assert(Control::releaseCalls==1 && Control::rights==0);
    assert(f.client.refs==1 && f.loop.refs==1);
    assert(f.snapshot().state==AsyncNotificationOwner::State::Closed);
}
static IOReturn beginCloseAction(OSObject *,void *arg,void *,void *,void *){
    auto &f=*static_cast<Fixture *>(arg);return f.owner.beginClose(f.context);
}
static void closeWithoutSubscription(){
    Fixture f;assert(f.owner.notifyZeroArgs(f.context)!=0);f.closed();
    assert(!Control::releaseCalls && !Control::rights);
    assert(Control::clientRetains==Control::clientReleases);
    assert(Control::loopRetains==Control::loopReleases);
    assert(f.rpc()!=0 && Control::migCleanupCalls==1 && !Control::releaseCalls);
}
static void beginCloseOnly(){
    Fixture f;assert(f.rpc()==0);
    assert(f.loop.runAction(beginCloseAction,&f.client,&f)==0);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnNotOpen && !Control::sendCalls);
    assert(f.rpc()!=0 && Control::rights==1 && Control::migCleanupCalls==1);
    f.closed();
}
static IOReturn gateMisuseAction(OSObject *,void *arg,void *,void *,void *){
    auto &f=*static_cast<Fixture *>(arg);
    assert(f.owner.notifyZeroArgs(f.context)==kIOReturnNotReady);
    assert(f.owner.close(f.context)==kIOReturnNotReady);return 0;
}
static void contexts(){
    Fixture f;
    assert(f.owner.adoptFromSuccessfulDispatch(f.context,f.args)==kIOReturnNotReady);
    assert(f.rpc()==0);
    assert(f.loop.runAction(gateMisuseAction,&f.client,&f)==0);
    for(unsigned mode=0;mode<2;++mode){
        Control::interrupt=mode==0;Control::interruptsEnabled=mode==0;
        assert(f.owner.notifyZeroArgs(f.context)==kIOReturnNotReady);
        assert(f.owner.close(f.context)==kIOReturnNotReady);
    }
    Control::interrupt=false;Control::interruptsEnabled=true;
    assert(!Control::sendCalls && !Control::releaseCalls);f.closed();
}
static bool containsReferences(const AsyncNotificationOwner &owner){
    auto *bytes=reinterpret_cast<const unsigned char *>(&owner);
    for(size_t i=0;i+56<=sizeof(owner);++i)
        if(!memcmp(bytes+i,Control::expected+1,56))return true;
    return false;
}
static void scrubbing(){
    Fixture f;assert(f.rpc()==0);assert(containsReferences(f.owner));
    f.closed();assert(!containsReferences(f.owner));
    for(unsigned i=0;i<8;++i)assert(f.refs[i]==Control::expected[i]);
}
static void adoptionContexts(){
    for(unsigned mode=0;mode<3;++mode){
        Fixture f;IOWorkLoop other;
        if(mode==0)f.context.generation=0;
        if(mode==1)f.client.inactive=true;
        if(mode==2)f.client.loop=&other;
        assert(f.rpc()!=0 && !Control::rights && !Control::releaseCalls);
        assert(f.client.refs==1 && f.loop.refs==1);
        f.context.generation=7;f.client.inactive=false;f.client.loop=&f.loop;
        assert(f.rpc()==0);f.closed();
    }
}
static void inactiveEmptyClose(){
    Fixture f;f.client.inactive=true;f.closed();
    assert(!Control::releaseCalls && !Control::clientRetains && !Control::loopRetains);
}
int main(int argc,char **argv){
    assert(argc==2);const int n=std::atoi(argv[1]);
    switch(n){case 0:success();break;case 1:malformed();break;
        case 2:duplicateAndGeneration();break;case 3:inFlightClose();break;
        case 4:retiringClose();break;case 5:sendErrors();break;
        case 6:releaseError();break;case 7:closeWithoutSubscription();break;
        case 8:beginCloseOnly();break;case 9:contexts();break;case 10:scrubbing();break;
        case 11:adoptionContexts();break;case 12:inactiveEmptyClose();break;
        default:assert(false);}
}
'''


class AsyncNotificationOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="awdl-notify-owner-", dir="/private/tmp")
        cls.folder = Path(cls.temporary.name)
        for name in ["IOKit/IOUserClient.h", "IOKit/IOWorkLoop.h", "machine/machine_routines.h"]:
            path = cls.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "mock.hpp"\n')
        (cls.folder / "mock.hpp").write_text(MOCK)
        (cls.folder / "harness.cpp").write_text(HARNESS)
        cls.binary = cls.folder / "owner"
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                        "-I", str(cls.folder), "-I", str(PROJECT / "src/awdl_kernel"),
                        str(PROJECT / "src/awdl_kernel/async_notification_owner.cpp"),
                        str(cls.folder / "harness.cpp"), "-o", str(cls.binary)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def run_scenario(self, number):
        result = subprocess.run([str(self.binary), str(number)], capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_success_right_and_zero_args(self): self.run_scenario(0)
    def test_rejected_shapes_leave_cleanup_to_mig(self): self.run_scenario(1)
    def test_duplicate_and_stale_context(self): self.run_scenario(2)
    def test_inflight_close_never_frees_right(self): self.run_scenario(3)
    def test_retiring_close_does_not_report_early_success(self): self.run_scenario(4)
    def test_send_error_does_not_consume_right(self): self.run_scenario(5)
    def test_release_error_is_not_retried(self): self.run_scenario(6)
    def test_close_without_subscription(self): self.run_scenario(7)
    def test_begin_close_blocks_admission(self): self.run_scenario(8)
    def test_gate_and_sleepable_guards_with_mock_context(self): self.run_scenario(9)
    def test_owned_opaque_references_scrubbed(self): self.run_scenario(10)
    def test_adoption_contexts_fail_without_ownership(self): self.run_scenario(11)
    def test_empty_owner_close_after_client_inactivity(self): self.run_scenario(12)


if __name__ == "__main__":
    unittest.main()
