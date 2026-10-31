"""Execute the actual worker with a fake ONCE scheduler; no real IOUC/port.

Host locks/thread calls model scheduling boundaries, not XNU IRQ behavior.
The separate SDK case compiles an unlinked kernel object without executing it.
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
#include <mutex>
#include <atomic>
using IOReturn=int32_t;
enum {kIOReturnSuccess=0,kIOReturnNotReady=1,kIOReturnBadArgument=2,
 kIOReturnNotPermitted=3,kIOReturnNoMemory=4,kIOReturnAborted=5,
 kIOReturnBusy=6,kIOReturnNotFound=7,kIOReturnUnsupported=8,kIOReturnError=9};
struct IOSimpleLock {std::mutex lock;};
using IOInterruptState=bool;
using thread_call_param_t=void *;
using thread_call_func_t=void(*)(void *,void *);
enum {THREAD_CALL_PRIORITY_KERNEL=1,THREAD_CALL_OPTIONS_ONCE=1};
struct ThreadCall {
 thread_call_func_t function=nullptr;void *owner=nullptr;
 bool queued=false,running=false,reschedule=false;
};
using thread_call_t=ThreadCall *;
struct Control {
 static thread_local bool interruptsEnabled,interrupt;
 static thread_local unsigned locks;
 static bool failLock,failCall;
 static unsigned allocatedLocks,freedLocks,allocatedCalls,enters,cancels;
 static void (*onAllocate)();static void (*onEnter)();
 static IOSimpleLock lockPool[8];static ThreadCall callPool[8];
};
inline bool ml_at_interrupt_context(){return Control::interrupt;}
inline bool ml_get_interrupts_enabled(){return Control::interruptsEnabled;}
inline IOSimpleLock *IOSimpleLockAlloc(){
 assert(!Control::locks && !Control::interrupt && Control::interruptsEnabled);
 return Control::failLock?nullptr:&Control::lockPool[Control::allocatedLocks++];
}
inline void IOSimpleLockFree(IOSimpleLock *){++Control::freedLocks;}
inline IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *l){
 const bool saved=Control::interruptsEnabled;Control::interruptsEnabled=false;
 l->lock.lock();++Control::locks;return saved;
}
inline void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *l,IOInterruptState saved){
 assert(Control::locks);--Control::locks;l->lock.unlock();Control::interruptsEnabled=saved;
}
inline thread_call_t thread_call_allocate_with_options(thread_call_func_t f,void *o,int p,int flags){
 assert(!Control::locks && p==THREAD_CALL_PRIORITY_KERNEL && flags==THREAD_CALL_OPTIONS_ONCE);
 if(Control::onAllocate)Control::onAllocate();
 if(Control::failCall)return nullptr;
 auto &c=Control::callPool[Control::allocatedCalls++];c.function=f;c.owner=o;return &c;
}
inline bool thread_call_enter(thread_call_t c){
 assert(Control::locks && !Control::interruptsEnabled);++Control::enters;
 if(Control::onEnter)Control::onEnter();
 if(c->running){const bool prior=c->reschedule;c->reschedule=true;return prior;}
 const bool prior=c->queued;c->queued=true;return prior;
}
inline bool thread_call_cancel(thread_call_t c){
 assert(Control::locks && !Control::interruptsEnabled);++Control::cancels;
 if(c->reschedule){c->reschedule=false;return true;}
 if(c->queued){c->queued=false;return true;}return false;
}
'''

FAKE_SESSION = r'''
#pragma once
#define AIRPORT_AWDL_EVENT_PIPE_SESSION_HPP
#include "mock.hpp"
#include "event_pipe_core.hpp"
#include "legacy_post_observer_core.hpp"
#include <vector>
namespace AWDLKernel {
class EventPipeWorker;
class EventPipeSession final {
public:
 struct PublishResult {IOReturn result=kIOReturnNotReady,notification=kIOReturnNotReady;
  uint32_t message=0,committed=0,dropped=0,full=0;
  uint32_t codecAttempted=0,codecError=0,codecRejectMask=0;};
 EventPipeCore core;
 std::vector<PublishResult> script;
 size_t index=0;uint32_t calls=0,accesses=0,closes=0;
 void (*duringDrain)(EventPipeSession &)=nullptr;
 EventPipeSession(){assert(core.beginCreate() && core.finishCreate(true));}
 IOReturn bindWorker(EventPipeWorker &,const ObserverHandle &);
 EventPipeCore::Phase phase()const{return core.phase();}
 PublishResult drainOne(){
  assert(!Control::locks && Control::interruptsEnabled && !Control::interrupt);
  ++calls;if(!core.acquire())return {};
  ++accesses;if(duringDrain)duringDrain(*this);
  PublishResult result;if(index<script.size())result=script[index++];
  else result.result=kIOReturnNotFound;
  assert(core.release());return result;
 }
 void beginClose(){++closes;core.beginClose();}
};
}
'''

HARNESS = r'''
#include "event_pipe_worker.hpp"
#include "fake_session.hpp"
#include <cstdlib>
#include <thread>
#include <chrono>
using namespace AWDLKernel;
thread_local bool Control::interruptsEnabled=true,Control::interrupt=false;
thread_local unsigned Control::locks=0;
bool Control::failLock=false,Control::failCall=false;
unsigned Control::allocatedLocks=0,Control::freedLocks=0,Control::allocatedCalls=0;
unsigned Control::enters=0,Control::cancels=0;
void (*Control::onAllocate)()=nullptr;void (*Control::onEnter)()=nullptr;
IOSimpleLock Control::lockPool[8];ThreadCall Control::callPool[8];
IOReturn EventPipeSession::bindWorker(EventPipeWorker &w,const ObserverHandle &h){return w.prepare(*this,h);}
using R=EventPipeSession::PublishResult;
static R committed(){R r;r.result=0;r.notification=0;r.committed=1;return r;}
static R code(IOReturn v){R r;r.result=v;return r;}
struct Fixture {
 EventPipeSession session;EventPipeWorker worker;ObserverHandle handle{0x1234,7};
 void prepare(){assert(session.bindWorker(worker,handle)==0);assert(worker.matchesBinding(handle));}
 void kick(){auto v=worker.kickFromProducer(handle);assert(v==EventPipeWorker::KickStatus::Scheduled ||
  v==EventPipeWorker::KickStatus::Coalesced);}
 ThreadCall &call(){assert(Control::allocatedCalls);return Control::callPool[Control::allocatedCalls-1];}
 void dequeue(){auto &c=call();assert(c.queued && !c.running);c.queued=false;c.running=true;}
 void invoke(){auto &c=call();assert(c.running);c.function(c.owner,nullptr);c.running=false;
  if(c.reschedule){c.reschedule=false;c.queued=true;}}
 void run(){dequeue();invoke();}
 void close(){worker.beginClose();assert(worker.pollStopped()==0);}
};
static void emptyAndCoalesced(){
 Fixture f;assert(f.worker.pollStopped()==kIOReturnBusy);f.prepare();
 assert(f.worker.kickFromProducer(f.handle)==EventPipeWorker::KickStatus::Scheduled);
 assert(f.worker.kickFromProducer(f.handle)==EventPipeWorker::KickStatus::Coalesced);
 assert(f.worker.snapshot().queued==1 && Control::enters==2);f.run();
 auto s=f.worker.snapshot();assert(s.callbacks==1 && s.attempts==1 && s.empty==1);
 assert(!s.queued && !s.running && s.coalesced==1);f.close();
}
static void boundedRearm(){
 Fixture f;f.prepare();for(unsigned i=0;i<35;++i)f.session.script.push_back(committed());
 f.kick();f.run();auto s=f.worker.snapshot();assert(s.attempts==16 && s.rearmed==1 && s.queued);
 f.run();s=f.worker.snapshot();assert(s.attempts==32 && s.rearmed==2 && s.queued);
 f.run();s=f.worker.snapshot();assert(s.committed==35 && s.empty==1 && s.attempts==36);
 assert(!s.queued && Control::enters==3);f.close();
}
static void droppedAndFull(){
 Fixture f;f.prepare();R bad=code(kIOReturnUnsupported);bad.dropped=1;
 R full=committed();full.committed=0;full.full=full.dropped=1;
 for(unsigned i=0;i<16;++i)f.session.script.push_back(i&1?full:bad);
 f.kick();f.run();auto s=f.worker.snapshot();assert(s.dropped==16 && s.full==8);
 assert(!s.faults && s.rearmed==1);f.run();assert(f.worker.snapshot().empty==1);f.close();
}
static void parked(){
 Fixture f;f.prepare();f.session.script={code(kIOReturnBusy),code(kIOReturnNotReady),committed()};
 f.kick();f.run();assert(Control::enters==1 && !f.call().queued && f.session.calls==1);
 f.kick();f.run();assert(Control::enters==2 && !f.call().queued && f.session.calls==2);
 f.kick();f.run();auto s=f.worker.snapshot();assert(s.busy==1 && s.notReady==1 && s.committed==1);
 assert(s.empty==1 && !s.rearmed && !s.faults);f.close();
}
static void notifyAndInvariantFaults(){
 for(unsigned i=0;i<8;++i){
  Fixture f;f.prepare();R r=committed();
  switch(i){case 0:r.notification=kIOReturnError;break;
   case 1:r.notification=kIOReturnNotReady;break;
   case 2:r.full=r.dropped=1;break;case 3:r.committed=0;break;
   case 4:r=code(kIOReturnUnsupported);break;
   case 5:r=code(kIOReturnBadArgument);break;
   case 6:r=code(kIOReturnUnsupported);r.dropped=2;break;
   case 7:r.committed=0;r.full=r.dropped=1;r.notification=kIOReturnError;break;}
  f.session.script={r,committed()};f.kick();f.run();auto s=f.worker.snapshot();
  assert(s.faults==1 && !s.queued && f.session.calls==1 && f.session.closes==1);
  assert(f.worker.kickFromProducer(f.handle)==EventPipeWorker::KickStatus::NotArmed);
  assert(f.worker.pollStopped()==0 && f.session.accesses==1);
 }
}
static void cancelBeforeRun(){
 Fixture f;f.prepare();f.kick();f.worker.beginClose();assert(!f.call().queued);
 assert(f.worker.pollStopped()==0 && f.session.calls==0);
 assert(f.worker.kickFromProducer(f.handle)==EventPipeWorker::KickStatus::NotArmed);
 assert(!f.worker.matchesBinding(f.handle));f.worker.beginClose();assert(f.worker.pollStopped()==0);
}
static void dequeueCloseGap(){
 Fixture f;f.prepare();f.kick();f.dequeue();f.worker.beginClose();
 assert(f.worker.pollStopped()==kIOReturnBusy && f.worker.snapshot().queued==1);
 f.invoke();assert(f.worker.pollStopped()==0 && f.session.calls==0);
}
static Fixture *current=nullptr;
static void closeInDrain(EventPipeSession &){
 auto &f=*current;assert(f.worker.snapshot().running==1);f.worker.beginClose();
 assert(f.worker.pollStopped()==kIOReturnBusy);f.session.beginClose();
}
static void closeRunning(){
 Fixture f;f.prepare();current=&f;f.session.script={committed(),committed()};
 f.session.duringDrain=closeInDrain;f.kick();f.run();
 assert(f.worker.pollStopped()==0 && f.session.calls==1 && f.session.accesses==1);
}
static void kickInDrain(EventPipeSession &s){
 auto &f=*current;f.kick();f.kick();s.duringDrain=nullptr;
 assert(f.call().running && f.call().reschedule && !f.call().queued);
}
static void onceReentry(){
 Fixture f;f.prepare();current=&f;f.session.script={committed()};f.session.duringDrain=kickInDrain;
 f.kick();f.run();assert(f.call().queued && !f.call().running);
 auto s=f.worker.snapshot();assert(s.callbacks==1 && s.queued && s.committed==1);
 f.run();assert(f.worker.snapshot().callbacks==2 && !f.call().queued);f.close();
}
static void closeAfterReschedule(EventPipeSession &s){
 auto &f=*current;f.kick();assert(f.call().reschedule);f.worker.beginClose();
 assert(!f.call().reschedule && f.worker.pollStopped()==kIOReturnBusy);s.duringDrain=nullptr;
}
static void cancelReschedule(){
 Fixture f;f.prepare();current=&f;f.session.script={committed()};
 f.session.duringDrain=closeAfterReschedule;f.kick();f.run();
 assert(!f.call().queued && f.worker.pollStopped()==0 && f.session.calls==1);
}
static void staleAndIRQ(){
 Fixture f;f.prepare();auto h=f.handle;h.generation++;
 assert(!f.worker.matchesBinding(h) && f.worker.kickFromProducer(h)==EventPipeWorker::KickStatus::Stale);
 h=f.handle;h.client++;assert(f.worker.kickFromProducer(h)==EventPipeWorker::KickStatus::Stale);
 Control::interrupt=true;Control::interruptsEnabled=false;f.kick();
 assert(!Control::interruptsEnabled);Control::interrupt=false;Control::interruptsEnabled=true;
 assert(f.session.calls==0);f.run();f.close();
}
static void prepareRejected(){
 Fixture f;auto h=f.handle;h.generation=0;
 assert(f.session.bindWorker(f.worker,h)==kIOReturnBadArgument);
 Control::interrupt=true;assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnNotPermitted);
 Control::interrupt=false;Control::interruptsEnabled=false;
 assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnNotPermitted);
 Control::interruptsEnabled=true;f.prepare();
 assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnNotReady);f.close();
 assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnNotReady);
}
static void allocationFailures(){
 Fixture a;Control::failLock=true;
 assert(a.session.bindWorker(a.worker,a.handle)==kIOReturnNoMemory);
 assert(a.worker.pollStopped()==0 && !Control::allocatedCalls);Control::failLock=false;
 Fixture b;Control::failCall=true;
 assert(b.session.bindWorker(b.worker,b.handle)==kIOReturnNoMemory);
 assert(b.worker.pollStopped()==0 && Control::freedLocks==1 && !Control::allocatedCalls);
}
static void closeDuringAllocate(){
 current->worker.beginClose();assert(current->worker.pollStopped()==kIOReturnBusy);
 assert(current->worker.kickFromProducer(current->handle)==EventPipeWorker::KickStatus::NotArmed);
}
static void preparingClose(){
 Fixture f;current=&f;Control::onAllocate=closeDuringAllocate;
 assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnAborted);
 assert(f.worker.pollStopped()==0 && Control::allocatedCalls==1 && !Control::enters);
 assert(!f.worker.matchesBinding(f.handle));
}
static void alreadyClosingSession(){
 Fixture f;f.prepare();f.session.beginClose();f.kick();f.run();
 assert(f.session.accesses==0 && f.worker.snapshot().notReady==1);
 assert(!f.call().queued);f.close();
}
static std::atomic<bool> enterHeld{false},releaseEnter{false},closeReturned{false},pollReturned{false};
static void holdEnter(){enterHeld.store(true);while(!releaseEnter.load())std::this_thread::yield();}
static void enterCloseRace(){
 Fixture f;f.prepare();Control::onEnter=holdEnter;
 std::thread producer([&]{f.kick();});while(!enterHeld.load())std::this_thread::yield();
 std::thread closer([&]{f.worker.beginClose();closeReturned.store(true);});
 while(f.worker.matchesBinding(f.handle))std::this_thread::yield();
 IOReturn stopped=kIOReturnError;
 std::thread poll([&]{stopped=f.worker.pollStopped();pollReturned.store(true);});
 std::this_thread::sleep_for(std::chrono::milliseconds(10));
 assert(!closeReturned.load() && !pollReturned.load());
 releaseEnter.store(true);producer.join();closer.join();poll.join();
 assert(stopped==0 || stopped==kIOReturnBusy); // cancel/poll lock order may differ.
 assert(f.worker.pollStopped()==0 && f.session.calls==0 && !f.call().queued);
}
static void neverPreparedClose(){
 Fixture f;f.worker.beginClose();assert(f.worker.pollStopped()==0);
 assert(f.session.bindWorker(f.worker,f.handle)==kIOReturnNotReady && !Control::allocatedCalls);
}
static void finishSessionClose(EventPipeSession &s){
 s.beginClose();assert(s.core.acquireCloser() && s.core.finishClose(true));
 assert(s.phase()==EventPipeCore::Phase::Closed);
}
static void replacementRequiresTerminalOldSession(){
 Fixture f;assert(!f.worker.canReplaceBinding());f.prepare();
 assert(!f.worker.canReplaceBinding());f.worker.beginClose();
 assert(!f.worker.canReplaceBinding());assert(f.worker.pollStopped()==0);
 assert(f.session.phase()==EventPipeCore::Phase::Open && !f.worker.canReplaceBinding());
 f.session.beginClose();assert(!f.worker.canReplaceBinding());
 finishSessionClose(f.session);assert(f.worker.canReplaceBinding());
 // Replacing an observer's external typed pointer cannot rebind the old worker.
 Fixture newer;newer.handle.generation=8;newer.prepare();newer.session.script={committed()};
 // Its scheduler entry remains resident after the observer detaches it.
 auto &oldCall=Control::callPool[0];
 oldCall.function(oldCall.owner,nullptr); // Model a late raw entry; no Session access.
 assert(f.session.calls==0 && newer.session.calls==0 && f.worker.canReplaceBinding());
 assert(f.worker.kickFromProducer(newer.handle)==EventPipeWorker::KickStatus::NotArmed);
 newer.kick();newer.run();assert(newer.session.accesses==2 && f.session.accesses==0);
 newer.close();finishSessionClose(newer.session);assert(newer.worker.canReplaceBinding());
}
static void failedPreparationCannotAuthorizeReplacement(){
 Fixture empty;empty.worker.beginClose();finishSessionClose(empty.session);
 assert(!empty.worker.canReplaceBinding());
 Fixture failed;Control::failCall=true;
 assert(failed.session.bindWorker(failed.worker,failed.handle)==kIOReturnNoMemory);
 Control::failCall=false;finishSessionClose(failed.session);
 assert(failed.worker.pollStopped()==0 && !failed.worker.canReplaceBinding());
 Fixture aborted;current=&aborted;Control::onAllocate=closeDuringAllocate;
 assert(aborted.session.bindWorker(aborted.worker,aborted.handle)==kIOReturnAborted);
 finishSessionClose(aborted.session);assert(!aborted.worker.canReplaceBinding());
}
static void queuedOldCallbackBlocksReplacement(){
 Fixture f;f.prepare();f.kick();f.dequeue();f.worker.beginClose();
 // Even an independently terminal core cannot waive queued/running drain.
 finishSessionClose(f.session);assert(!f.worker.canReplaceBinding());
 assert(f.worker.pollStopped()==kIOReturnBusy);f.invoke();
 assert(f.worker.pollStopped()==0 && f.worker.canReplaceBinding() && !f.session.calls);
}
static R codecResult(uint32_t message,uint32_t error=0,uint32_t mask=0){
 R r=error?code(kIOReturnUnsupported):committed();r.message=message;
 r.codecAttempted=1;r.codecError=error;r.codecRejectMask=mask;
 if(error)r.dropped=1;return r;
}
static void numericCodecBuckets(){
 Fixture f;f.prepare();
 // This fake Session tests Worker accounting, not acceptance by a real codec.
 for(auto message:{46U,47U,48U,55U}){
  f.session.script.push_back(codecResult(message));
  f.session.script.push_back(codecResult(message,5,message==48?1:0));
 }
 f.session.script.push_back(codecResult(48,4,4));
 R full=codecResult(48);full.committed=0;full.full=full.dropped=1;
 f.session.script.push_back(full);f.kick();f.run();auto s=f.worker.snapshot();
 assert(s.received46==2&&s.received47==2&&s.received48==4&&s.receivedOther==2);
 assert(s.rejected46==1&&s.rejected47==1&&s.rejected48==2&&s.rejectedOther==1);
 assert(s.committed46==1&&s.committed47==1&&s.committed48==1&&s.committedOther==1);
 assert(s.lastCodecMessage==48&&!s.lastCodecError&&s.last48RejectMask==4&&s.seen48RejectMask==5);
 assert(s.full==1&&s.dropped==6&&!s.faults&&s.empty==1);
 f.kick();f.run();auto empty=f.worker.snapshot();
 assert(empty.empty==2&&empty.received48==4&&empty.lastCodecMessage==48&&!empty.lastCodecError);
 assert(empty.last48RejectMask==4&&empty.seen48RejectMask==5);f.close();
}
static void absentAttemptCannotManufactureCodecObservation(){
 Fixture f;f.prepare();R r=committed();r.message=48;r.codecError=5;r.codecRejectMask=0xff;
 f.session.script={r};f.kick();f.run();auto s=f.worker.snapshot();
 assert(s.committed==1&&!s.received48&&!s.rejected48&&!s.committed48);
 assert(!s.lastCodecMessage&&!s.lastCodecError&&!s.last48RejectMask&&!s.seen48RejectMask);f.close();
}
static void notificationFaultIsNotCodecRejection(){
 Fixture f;f.prepare();R r=codecResult(47);r.notification=kIOReturnError;
 f.session.script={r};f.kick();f.run();auto s=f.worker.snapshot();
 assert(s.faults==1&&s.received47==1&&s.committed47==1&&!s.rejected47);
 assert(s.lastCodecMessage==47&&!s.lastCodecError&&!s.last48RejectMask&&!s.seen48RejectMask);
 assert(f.worker.pollStopped()==0);
}
int main(int argc,char **argv){assert(argc==2);switch(std::atoi(argv[1])){
 case 0:emptyAndCoalesced();break;case 1:boundedRearm();break;case 2:droppedAndFull();break;
 case 3:parked();break;case 4:notifyAndInvariantFaults();break;case 5:cancelBeforeRun();break;
 case 6:dequeueCloseGap();break;case 7:closeRunning();break;case 8:onceReentry();break;
 case 9:cancelReschedule();break;case 10:staleAndIRQ();break;case 11:prepareRejected();break;
 case 12:allocationFailures();break;case 13:preparingClose();break;
 case 14:alreadyClosingSession();break;case 15:enterCloseRace();break;
 case 16:neverPreparedClose();break;case 17:replacementRequiresTerminalOldSession();break;
 case 18:failedPreparationCannotAuthorizeReplacement();break;
 case 19:queuedOldCallbackBlocksReplacement();break;case 20:numericCodecBuckets();break;
 case 21:absentAttemptCannotManufactureCodecObservation();break;
 case 22:notificationFaultIsNotCodecRejection();break;default:assert(false);}}
'''


class EventPipeWorkerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="awdl-worker-", dir="/private/tmp")
        cls.folder = Path(cls.temporary.name)
        for name in ["IOKit/IOLocks.h", "IOKit/IOReturn.h", "kern/thread_call.h",
                     "machine/machine_routines.h"]:
            path = cls.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "mock.hpp"\n')
        (cls.folder / "mock.hpp").write_text(MOCK)
        (cls.folder / "fake_session.hpp").write_text(FAKE_SESSION)
        (cls.folder / "harness.cpp").write_text(HARNESS)
        cls.binary = cls.folder / "worker"
        subprocess.run(["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                        "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-pthread",
                        "-include", str(cls.folder / "fake_session.hpp"),
                        "-I", str(cls.folder), "-I", str(PROJECT / "src/awdl_kernel"),
                        str(PROJECT / "src/awdl_kernel/event_pipe_worker.cpp"),
                        str(cls.folder / "harness.cpp"), "-o", str(cls.binary)],
                       check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls): cls.temporary.cleanup()

    def run_scenario(self, number):
        result = subprocess.run([str(self.binary), str(number)], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_empty_and_pending_kicks_coalesce(self): self.run_scenario(0)
    def test_sixteen_event_batches_and_once_rearm(self): self.run_scenario(1)
    def test_consumed_schema_drops_and_ring_full_are_progress(self): self.run_scenario(2)
    def test_busy_and_notready_park_without_polling(self): self.run_scenario(3)
    def test_notify_errors_and_impossible_results_fault_without_replay(self): self.run_scenario(4)
    def test_cancel_pending_before_callback(self): self.run_scenario(5)
    def test_cancel_false_in_dequeue_to_callback_gap_stays_busy(self): self.run_scenario(6)
    def test_close_while_draining_preserves_session_operation(self): self.run_scenario(7)
    def test_kick_running_once_defers_without_overlap(self): self.run_scenario(8)
    def test_cancel_running_once_reschedule(self): self.run_scenario(9)
    def test_immutable_handle_and_irq_safe_kick(self): self.run_scenario(10)
    def test_prepare_context_and_terminal_binding(self): self.run_scenario(11)
    def test_unpublished_allocation_failure_cleanup(self): self.run_scenario(12)
    def test_close_during_preparation_never_publishes_armed(self): self.run_scenario(13)
    def test_session_core_refuses_resource_access_after_close(self): self.run_scenario(14)
    def test_enter_completion_serialized_with_close_and_poll(self): self.run_scenario(15)
    def test_close_before_prepare_is_terminal(self): self.run_scenario(16)
    def test_replace_only_after_stopped_and_old_session_closed(self): self.run_scenario(17)
    def test_failed_or_aborted_prepare_never_authorizes_replacement(self): self.run_scenario(18)
    def test_late_queued_callback_blocks_replacement(self): self.run_scenario(19)
    def test_codec_buckets_reject_masks_and_empty_callbacks_preserve_observation(self): self.run_scenario(20)
    def test_absent_codec_attempt_cannot_manufacture_counts_or_last(self): self.run_scenario(21)
    def test_notification_fault_preserves_successful_codec_commit(self): self.run_scenario(22)


if __name__ == "__main__": unittest.main()
