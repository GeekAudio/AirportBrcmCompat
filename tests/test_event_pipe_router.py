"""Actual unwired router with explicit registry/Session/KPI models.

Tests routing/entry accounting, not real task authorization, observer reopen,
Mach rights, threadcall shutdown, provider teardown, or installed IOUC routes.
The real Session composition has its separate ASan/UBSan fixture.
"""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]
MOCK = r'''
#pragma once
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <thread>
#include "event_pipe_core.hpp"
using IOReturn=int32_t;using IOOptionBits=uint32_t;using task_t=void *;
enum {kIOReturnSuccess=0,kIOReturnBusy=1,kIOReturnNotReady=2,kIOReturnNoMemory=3,
 kIOReturnNoResources=4,kIOReturnAborted=5,kIOReturnBadArgument=6,
 kIOReturnNotPrivileged=7,kIOReturnNotOpen=8};
struct IOExternalMethodArguments {bool valid=true;};
class IOService {};
class IOUserClient {};
class IOMemoryDescriptor {public:unsigned refs=1;};
class IOWorkLoop {public:static thread_local bool held;bool inGate()const;};
struct IOSimpleLock {std::mutex mutex;};
using IOInterruptState=unsigned;
struct Test {
 static thread_local bool irqLock,interrupt,interruptsEnabled;
 static thread_local task_t task;
 static bool failLock,forceBusy,allowReopen;
 static std::atomic<unsigned> creates,closes,maps,adopts,rightReleases,leases,observerMarks;
 static void (*onAcquire)();static void (*onCreate)();static void (*onMap)();static void (*onAdopt)();
 static void (*onBeginClose)();
 static std::atomic<unsigned> observerEpoch,closedObserverEpoch;
 static void *sessionAddresses[8];static IOService *admitted[8];
};
inline bool IOWorkLoop::inGate()const{assert(!Test::irqLock);return held;}
inline bool ml_at_interrupt_context(){return Test::interrupt;}
inline bool ml_get_interrupts_enabled(){return Test::interruptsEnabled;}
inline task_t current_task(){return Test::task;}
inline IOSimpleLock *IOSimpleLockAlloc(){assert(!Test::irqLock);return Test::failLock?nullptr:new IOSimpleLock;}
inline IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock){
 assert(!Test::irqLock);lock->mutex.lock();Test::irqLock=true;return 0;
}
inline void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock,IOInterruptState){
 assert(Test::irqLock);Test::irqLock=false;lock->mutex.unlock();
}
namespace AWDLKernel {
struct VersionCall {};
class DriverVersionBackend {};
enum class ClientStatus {Passed,Missing,Closing};
struct ClientRegistry;
class ClientWorkLease {
public:
 ClientRegistry *registry=nullptr;~ClientWorkLease();
 IOUserClient *client()const;IOService *provider()const;IOService *controller()const;
 task_t owner()const;uint64_t generation()const;IOWorkLoop *workLoop()const;
};
struct ClientRegistry {
 IOUserClient *client=nullptr;IOService *provider=nullptr,*controller=nullptr;
 IOWorkLoop loop;uint64_t generation=3;bool closing=false;
 task_t owner=reinterpret_cast<task_t>(uintptr_t(2));
 ClientStatus acquire(IOUserClient *key,ClientWorkLease &out){
  assert(!Test::irqLock&&!out.registry);if(key!=client)return ClientStatus::Missing;
  if(closing)return ClientStatus::Closing;out.registry=this;++Test::leases;
  if(Test::onAcquire){auto h=Test::onAcquire;Test::onAcquire=nullptr;h();}return ClientStatus::Passed;
 }
 ClientStatus acquireClosing(IOUserClient *key,ClientWorkLease &out){
  assert(!Test::irqLock&&!out.registry);if(key!=client)return ClientStatus::Missing;
  out.registry=this;++Test::leases;return ClientStatus::Passed;
 }
};
inline ClientWorkLease::~ClientWorkLease(){if(registry)--Test::leases;}
inline IOUserClient *ClientWorkLease::client()const{return registry->client;}
inline IOService *ClientWorkLease::provider()const{return registry->provider;}
inline IOService *ClientWorkLease::controller()const{return registry->controller;}
inline task_t ClientWorkLease::owner()const{return registry->owner;}
inline uint64_t ClientWorkLease::generation()const{return registry->generation;}
inline IOWorkLoop *ClientWorkLease::workLoop()const{return &registry->loop;}
struct ObserverHandle {};
namespace LegacyPostObserver {
inline void beginClose(IOUserClient *,ObserverHandle &){assert(!Test::irqLock);++Test::observerMarks;Test::closedObserverEpoch=Test::observerEpoch.load();}
inline void beginCloseProvider(IOService *,ObserverHandle &){assert(!Test::irqLock);++Test::observerMarks;}
inline void beginCloseController(IOService *){assert(!Test::irqLock);++Test::observerMarks;}
}
class EventPipeSession {
 EventPipeCore core;bool adopted=false;unsigned epoch=0;
public:
 struct WorkerSnapshot {uint64_t callbacks=0,committed=0,dropped=0,full=0,faults=0;uint32_t queued=0,running=0;
  uint64_t received46=0,received47=0,received48=0,receivedOther=0;
  uint64_t rejected46=0,rejected47=0,rejected48=0,rejectedOther=0;
  uint64_t committed46=0,committed47=0,committed48=0,committedOther=0;
  uint32_t lastCodecMessage=0,lastCodecError=0,last48RejectMask=0,seen48RejectMask=0;};
 WorkerSnapshot workerValues{};
 WorkerSnapshot workerSnapshot()const{assert(!Test::irqLock);return workerValues;}
 IOReturn create(ClientRegistry &registry,IOUserClient *,const DriverVersionBackend &,const VersionCall &){
  assert(!Test::irqLock&&!IOWorkLoop::held);
  if(!core.beginCreate())return kIOReturnBusy;
  unsigned index=Test::creates++;assert(index<8);Test::sessionAddresses[index]=this;
  if(Test::onCreate)Test::onCreate();
  bool authorized=true;
  for(auto *provider:Test::admitted)if(provider==registry.provider)authorized=false;
  if(Test::allowReopen)authorized=true; // Explicit adapter model in the late-old-close test ONLY.
  if(authorized){++Test::observerEpoch;epoch=Test::observerEpoch.load();
   for(auto &provider:Test::admitted)if(!provider){provider=registry.provider;break;}}
  // Explicit model of current observer's permanent per-provider registration:
  // it never pretends a second new Session can reopen that old registration.
  if(core.finishCreate(authorized))return 0;
  close();return authorized?kIOReturnAborted:kIOReturnNotReady;
 }
 void beginClose(){assert(!Test::irqLock);if(Test::onBeginClose)Test::onBeginClose();core.beginClose();}
 IOReturn close(){
  assert(!Test::irqLock&&!IOWorkLoop::held);core.beginClose();
  if(core.phase()==EventPipeCore::Phase::Closed)return 0;
  if(!core.acquireCloser())return kIOReturnBusy;
  if(Test::forceBusy){assert(core.finishClose(false));return kIOReturnBusy;}
  if(epoch){ObserverHandle ignored;LegacyPostObserver::beginClose(nullptr,ignored);}
  ++Test::closes;if(adopted){++Test::rightReleases;adopted=false;}
  assert(core.finishClose(true));return 0;
 }
 EventPipeCore::Phase phase()const{return core.phase();}
 IOReturn retainMemoryForType(uint32_t,IOOptionBits *options,IOMemoryDescriptor **memory){
  assert(!Test::irqLock&&!IOWorkLoop::held);
  if(!core.acquire())return kIOReturnNotOpen;
  if(Test::onMap)Test::onMap();
  const bool open=core.phase()==EventPipeCore::Phase::Open;
  if(open){static IOMemoryDescriptor descriptor;++Test::maps;++descriptor.refs;*memory=&descriptor;*options=0x1000;}
  assert(core.release());return open?0:kIOReturnNotReady;
 }
 IOReturn subscribeFromSuccessfulDispatch(const IOExternalMethodArguments &args){
  assert(!Test::irqLock&&IOWorkLoop::held);
  if(!core.acquire())return kIOReturnNotOpen;
  if(!args.valid){assert(core.release());return kIOReturnBadArgument;}
  if(adopted){assert(core.release());return kIOReturnBusy;}
  adopted=true;++Test::adopts;
  if(Test::onAdopt)Test::onAdopt();assert(core.release());return 0;
 }
 bool lateOldEntry(){assert(!Test::irqLock);if(!core.acquire())return false;core.release();return true;}
};
}
'''

HARNESS = r'''
#include "event_pipe_router.hpp"
using namespace AWDLKernel;
thread_local bool Test::irqLock=false,Test::interrupt=false,Test::interruptsEnabled=true;
thread_local bool IOWorkLoop::held=false;
thread_local task_t Test::task=reinterpret_cast<task_t>(uintptr_t(2));
bool Test::failLock=false,Test::forceBusy=false,Test::allowReopen=false;
#define C(n) std::atomic<unsigned> Test::n{0}
C(creates);C(closes);C(maps);C(adopts);C(rightReleases);C(leases);C(observerMarks);
C(observerEpoch);C(closedObserverEpoch);
#undef C
void (*Test::onAcquire)()=nullptr;void (*Test::onCreate)()=nullptr;
void (*Test::onMap)()=nullptr;void (*Test::onAdopt)()=nullptr;
void (*Test::onBeginClose)()=nullptr;
void *Test::sessionAddresses[8]{};IOService *Test::admitted[8]{};
struct Fixture {
 EventPipeRouter router;ClientRegistry registry;DriverVersionBackend backend;
 IOUserClient client,foreign;VersionCall verification;IOExternalMethodArguments args;
 Fixture(){registry.client=&client;registry.provider=reinterpret_cast<IOService *>(uintptr_t(0x1000));
  registry.controller=reinterpret_cast<IOService *>(uintptr_t(0x2000));}
 void prepare(){assert(!router.prepare(registry,backend));assert(router.ready());}
 IOReturn create(){return router.create(&client,verification);}
 IOReturn subscribe(){IOWorkLoop::held=true;const auto r=router.subscribeFromSuccessfulDispatch(&client,args);IOWorkLoop::held=false;return r;}
 ~Fixture(){assert(!Test::leases&&!Test::irqLock);}
};
static Fixture *fixture=nullptr;static std::atomic<bool> entered{false},resume{false};
static thread_local bool pauseThisBeginClose=false;
static void pauseCreate(){entered=true;while(!resume.load())std::this_thread::yield();}
static void pauseOldBeginClose(){if(pauseThisBeginClose)pauseCreate();}
static void ownedMark(){fixture->router.markClientClosing(&fixture->client);}
static void mapDestroy(){assert(fixture->router.destroy(&fixture->client)==kIOReturnBusy);}
static void asyncClose(){ownedMark();fixture->registry.closing=true;}
static void scenario(unsigned n){
 if(n==0){
  Fixture f;assert(!f.router.ready());assert(f.create()==kIOReturnNotReady);Test::failLock=true;
  assert(f.router.prepare(f.registry,f.backend)==kIOReturnNoMemory);Test::failLock=false;f.prepare();
  assert(!f.router.prepare(f.registry,f.backend));DriverVersionBackend other;
  assert(f.router.prepare(f.registry,other)==kIOReturnBusy);
  assert(!f.router.destroy(&f.client)&&f.router.snapshot().used==0);
  assert(!f.create()&&f.create()==kIOReturnBusy);auto state=f.router.snapshot();
  assert(state.used==1&&state.live==1&&!state.retiring);
  IOMemoryDescriptor *md=nullptr;IOOptionBits options=0;
  assert(!f.router.retainMemoryForType(&f.client,1,&options,&md)&&md&&options==0x1000);--md->refs;
  assert(!f.subscribe()&&Test::adopts==1);assert(!f.router.destroy(&f.client));
  assert(!f.registry.closing&&Test::rightReleases==1&&!f.router.snapshot().retiring);
  assert(!f.router.destroy(&f.client));assert(f.router.snapshot().terminal==1&&f.router.ready());
 }else if(n==1){
  Fixture f;f.prepare();fixture=&f;Test::onCreate=pauseCreate;IOReturn created=0;
  std::thread creator([&]{created=f.create();});while(!entered.load())std::this_thread::yield();
  assert(f.create()==kIOReturnBusy&&f.router.snapshot().creating==1);
  assert(f.router.destroy(&f.client)==kIOReturnBusy&&!f.router.snapshot().retiring);
  resume=true;creator.join();Test::onCreate=nullptr;
  assert(created!=0&&f.router.snapshot().terminal==1&&Test::creates==1);
 }else if(n==2){
  Fixture f;f.prepare();fixture=&f;Test::onAcquire=ownedMark;
  assert(f.create()==kIOReturnNotReady&&f.router.snapshot().retiring&&f.router.snapshot().used==0&&!f.router.ready());
  assert(!Test::creates); // mark won before the leased creator reserved a slot.
 }else if(n==3){
  Fixture f;f.prepare();assert(!f.create());fixture=&f;Test::onMap=mapDestroy;
  IOMemoryDescriptor *md=reinterpret_cast<IOMemoryDescriptor *>(uintptr_t(1));IOOptionBits options=99;
  assert(f.router.retainMemoryForType(&f.client,1,&options,&md)!=0&&!md&&!options&&!Test::maps);
  Test::onMap=nullptr;assert(!f.router.collect(&f.client)&&f.router.snapshot().terminal==1);
 }else if(n==4){
  Fixture f;f.prepare();assert(!f.create());fixture=&f;Test::onAdopt=asyncClose;
  assert(f.subscribe()==0&&Test::adopts==1&&!Test::rightReleases);
  assert(f.router.snapshot().retiring&&f.registry.closing&&!f.router.ready());
  Test::onAdopt=nullptr;Test::task=reinterpret_cast<task_t>(uintptr_t(9));
  assert(!f.router.collect(&f.client)&&Test::rightReleases==1); // Trusted stop task, not RPC authorization.
 }else if(n==5){
  Fixture f;f.prepare();assert(!f.create());Test::forceBusy=true;
  assert(f.router.destroy(&f.client)==kIOReturnBusy&&f.router.snapshot().closing==1);
  assert(f.create()==kIOReturnBusy&&Test::creates==1);Test::forceBusy=false;
  assert(f.create()==kIOReturnNotReady&&Test::creates==2&&f.router.snapshot().terminal==2);
  assert(!f.registry.closing&&!f.router.snapshot().retiring); // Honest observer reopen failure.
  auto *old=static_cast<EventPipeSession *>(Test::sessionAddresses[0]);
  auto *next=static_cast<EventPipeSession *>(Test::sessionAddresses[1]);
  assert(old!=next&&!old->lateOldEntry()&&!next->lateOldEntry());
 }else if(n==6){
  Fixture f;f.prepare();assert(!f.create());assert(!f.router.destroy(&f.client));
  for(unsigned i=1;i<8;++i)assert(f.create()==kIOReturnNotReady);
  assert(Test::creates==8&&f.router.snapshot().used==8&&f.router.snapshot().terminal==8);
  assert(f.create()==kIOReturnNoResources&&Test::creates==8);
  for(unsigned i=0;i<8;++i)for(unsigned j=0;j<i;++j)assert(Test::sessionAddresses[i]!=Test::sessionAddresses[j]);
  assert(f.router.ready()); // Admission predicate, not available-budget/event capability.
 }else if(n==7||n==8){
  Fixture f;f.prepare();assert(!f.create());
  if(n==7)f.router.markProviderClosing(f.registry.provider);else f.router.markControllerClosing(f.registry.controller);
  assert(f.router.snapshot().retiring&&f.router.snapshot().closing==1&&!Test::closes&&!f.router.ready());
  f.registry.closing=true;assert(!f.router.collect(&f.client)&&f.router.snapshot().terminal==1);
 }else if(n==9){
  Fixture f;f.prepare();assert(f.router.create(&f.foreign,f.verification)==kIOReturnNotReady);
  Test::task=reinterpret_cast<task_t>(uintptr_t(9));assert(f.create()==kIOReturnNotPrivileged);
  Test::task=f.registry.owner;IOWorkLoop::held=true;assert(f.create()==kIOReturnNotReady);IOWorkLoop::held=false;
  Test::interrupt=true;assert(f.create()==kIOReturnNotReady);Test::interrupt=false;
  assert(!f.create());f.args.valid=false;assert(f.subscribe()==kIOReturnBadArgument&&!Test::adopts);
  assert(!f.router.destroy(&f.client));assert(!f.router.snapshot().retiring);
 }else if(n==10){
  Fixture f;f.prepare();assert(!f.create());assert(!f.router.destroy(&f.client));
  assert(f.create()==kIOReturnNotReady);auto *first=static_cast<EventPipeSession *>(Test::sessionAddresses[0]);
  auto *second=static_cast<EventPipeSession *>(Test::sessionAddresses[1]);
  first->workerValues.callbacks=UINT64_C(0x100000002);first->workerValues.committed=7;
  first->workerValues.dropped=3;first->workerValues.full=2;first->workerValues.faults=1;first->workerValues.running=1;
  second->workerValues.callbacks=5;second->workerValues.committed=4;second->workerValues.dropped=3;
  second->workerValues.full=2;second->workerValues.faults=1;second->workerValues.queued=1;
  auto state=f.router.snapshot();
  assert(state.used==2&&state.workerCallbacks==UINT64_C(0x100000007));
  assert(state.workerCommitted==11&&state.workerDropped==6&&state.workerFull==4&&state.workerFaults==2);
  assert(state.workerQueued==1&&state.workerRunning==1);
 }else if(n==11){
  // This case deliberately supplies a reopen-capable Session/observer model.
  // The production router executes unchanged; it does not establish actual
  // adapter authorization or real observer reopen correctness.
  Fixture f;f.prepare();Test::allowReopen=true;assert(!f.create());
  Test::onBeginClose=pauseOldBeginClose;IOReturn late=99;
  std::thread oldDestroy([&]{pauseThisBeginClose=true;late=f.router.destroy(&f.client);});
  while(!entered.load())std::this_thread::yield();
  assert(!f.router.destroy(&f.client)); // A second destroy fully closes old Session.
  assert(f.router.snapshot().terminal==1&&Test::closedObserverEpoch==1);
  assert(!f.create()&&Test::observerEpoch==2&&f.router.snapshot().live==1);
  resume=true;oldDestroy.join();Test::onBeginClose=nullptr;
  assert(!late&&Test::closedObserverEpoch==1); // Late OLD close cannot close NEW observer.
  assert(f.router.snapshot().used==2&&f.router.snapshot().live==1);
  assert(!f.subscribe());assert(!f.router.destroy(&f.client)&&Test::closedObserverEpoch==2);
 }else if(n==12){
  Fixture f;f.prepare();Test::allowReopen=true;
  for(unsigned n=0;n<3;++n){assert(!f.create());assert(!f.router.destroy(&f.client));}
  auto &first=static_cast<EventPipeSession *>(Test::sessionAddresses[0])->workerValues;
  auto &second=static_cast<EventPipeSession *>(Test::sessionAddresses[1])->workerValues;
  auto &third=static_cast<EventPipeSession *>(Test::sessionAddresses[2])->workerValues;
  first.received46=UINT64_C(0x100000001);first.received47=2;first.received48=3;first.receivedOther=4;
  first.rejected46=1;first.rejected47=2;first.rejected48=1;first.rejectedOther=4;
  first.committed46=5;first.committed47=6;first.committed48=7;first.committedOther=8;
  first.lastCodecMessage=48;first.lastCodecError=5;first.last48RejectMask=1;first.seen48RejectMask=3;
  second.received46=9;second.received47=10;second.received48=11;second.receivedOther=12;
  second.rejected46=2;second.rejected47=3;second.rejected48=4;second.rejectedOther=5;
  second.committed46=13;second.committed47=14;second.committed48=15;second.committedOther=16;
  second.lastCodecMessage=47;second.lastCodecError=0;second.last48RejectMask=4;second.seen48RejectMask=12;
  third.callbacks=100; // Empty callbacks in a newer allocated slot are not observations.
  auto s=f.router.snapshot();
  assert(s.received46==UINT64_C(0x10000000a)&&s.received47==12&&s.received48==14&&s.receivedOther==16);
  assert(s.rejected46==3&&s.rejected47==5&&s.rejected48==5&&s.rejectedOther==9);
  assert(s.committed46==18&&s.committed47==20&&s.committed48==22&&s.committedOther==24);
  assert(s.lastCodecMessage==47&&!s.lastCodecError&&s.last48RejectMask==4&&s.seen48RejectMask==15);
  // Newest codec observation need not be the newest rejected48 observation.
  third.received46=1;third.lastCodecMessage=46;
  s=f.router.snapshot();assert(s.lastCodecMessage==46&&!s.lastCodecError&&s.last48RejectMask==4);
  // Later activity in an older slot does not redefine allocation-based last.
  first.lastCodecMessage=55;first.lastCodecError=3;first.last48RejectMask=16;first.seen48RejectMask|=16;
  s=f.router.snapshot();assert(s.lastCodecMessage==46&&s.last48RejectMask==4&&s.seen48RejectMask==31);
 }else abort();
}
int main(int argc,char **argv){assert(argc==2);scenario(unsigned(atoi(argv[1])));}
'''


class EventPipeRouterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="event-pipe-router-", dir="/private/tmp")
        cls.folder = Path(cls.temporary.name)
        for name in ["event_pipe_router.hpp", "event_pipe_router.cpp", "event_pipe_core.hpp"]:
            shutil.copyfile(PROJECT / "src/awdl_kernel" / name, cls.folder / name)
        (cls.folder / "event_pipe_session.hpp").write_text('#include "mock.hpp"\n')
        (cls.folder / "mock.hpp").write_text(MOCK)
        for name in ["IOKit/IOLocks.h", "kern/task.h", "machine/machine_routines.h"]:
            path = cls.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "mock.hpp"\n')
        (cls.folder / "harness.cpp").write_text(HARNESS)
        cls.binary = cls.folder / "router"
        result = subprocess.run(["xcrun", "clang++", "-std=c++14", "-pthread", "-Wall", "-Wextra",
                                 "-Werror", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                                 "-I", str(cls.folder), str(cls.folder / "event_pipe_router.cpp"),
                                 str(cls.folder / "harness.cpp"), "-o", str(cls.binary)],
                                capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check(self, number):
        result = subprocess.run([str(self.binary), str(number)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_prepare_owner_apis_and_selector4_keeps_registry_open(self): self.check(0)
    def test_actual_thread_create_vs_destroy_keeps_creating_barrier(self): self.check(1)
    def test_lifecycle_mark_after_acquire_before_slot_reservation_still_blocks_create(self): self.check(2)
    def test_map_vs_destroy_does_not_return_closed_descriptor(self): self.check(3)
    def test_successful_adopt_not_rewritten_when_owned_close_races(self): self.check(4)
    def test_busy_retry_fresh_session_and_honest_observer_reopen_failure(self): self.check(5)
    def test_eight_fresh_resident_slots_never_reused_and_exhaustion_explicit(self): self.check(6)
    def test_provider_mark_compares_saved_key_without_dereference(self): self.check(7)
    def test_controller_mark_compares_saved_key_without_dereference(self): self.check(8)
    def test_foreign_owner_gate_irq_and_bad_async_arguments_reject(self): self.check(9)
    def test_worker_numeric_sums_preserve_64bit_and_sample_outside_router_lock(self): self.check(10)
    def test_delayed_old_double_destroy_never_closes_new_same_uc_observer_cycle(self): self.check(11)
    def test_codec_sums_or_masks_and_allocation_based_last_ignore_empty_newer_slot(self): self.check(12)


if __name__ == "__main__":
    unittest.main()
