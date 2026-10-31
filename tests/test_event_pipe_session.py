"""Actual router/session/worker/MD/async-owner/ring/codec composition.

No real task authorization, producer capture, mapping, port, provider lifetime,
or network execution is proved here. Registry and observer are explicit models;
the production composition and its ownership components execute unchanged.
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
#include <cstring>
#include <mutex>
#include <memory>
#include <thread>
#include <vector>
using IOReturn=int32_t;
using IOOptionBits=uint32_t;
using task_t=void *;
// Host threading headers declare the userspace uint32_t port-name typedef.
// The kernel component instead consumes a pointer-sized kernel IPC port.
using MockKernelPort=void *;
#define mach_port_t MockKernelPort
using OSAsyncReference64=uint64_t[8];
using clock_sec_t=uint64_t;
using clock_usec_t=uint32_t;
enum {kOSAsyncRef64Count=8};
static constexpr mach_port_t MACH_PORT_NULL=nullptr;
static task_t const kernel_task=reinterpret_cast<task_t>(uintptr_t(1));
enum {kIOReturnSuccess=0,kIOReturnBadArgument=1,kIOReturnBusy=2,
 kIOReturnNotReady=3,kIOReturnNotOpen=4,kIOReturnInternalError=5,
 kIOReturnAborted=6,kIOReturnNotPrivileged=7,kIOReturnNoMemory=8,
 kIOReturnError=9,kIOReturnUnsupported=10,kIOReturnNotFound=11,kIOReturnNotPermitted=12,
 kIOReturnNoResources=13,
 kIOMemoryKernelUserShared=0x10000,kIODirectionInOut=3,
 kIOMapUserOptionsMask=0xfff,kIOMapReadOnly=0x1000};
class IOWorkLoop;
class IOMemoryDescriptor;
struct Control {
 static thread_local bool interrupt,interruptsEnabled;
 static thread_local task_t task;
 static std::atomic<int> allocations,alive,retains,releases,rights,migCleanup,
  sends,rightReleases,deliveries,ownerLeases,clockCalls,observerClosed;
 static int failAllocation,failSend;
 static clock_usec_t microseconds;
 static clock_sec_t seconds;
 static uint64_t expectedReference;
 static void (*onAllocation)();
 static void (*onSubscribe)();
 static void (*onTake)();
 static void (*onBeforeAction)();
 static void (*onSend)();
 static IOMemoryDescriptor *ring,*state;
};
class OSObject {public:virtual ~OSObject()=default;};
class IOWorkLoop:public OSObject {
 std::recursive_mutex mutex;
 static thread_local IOWorkLoop *held;
public:
 std::atomic<int> refs{1};
 using Action=IOReturn(*)(OSObject *,void *,void *,void *,void *);
 bool inGate() const{return held==this;}
 void retain(){++refs;}
 void release(){assert(!inGate()&&refs>1);--refs;}
 IOReturn runAction(Action f,OSObject *o,void *a=nullptr,void *b=nullptr,
                    void *c=nullptr,void *d=nullptr) {
  if(Control::onBeforeAction){auto hook=Control::onBeforeAction;Control::onBeforeAction=nullptr;hook();}
  std::lock_guard<std::recursive_mutex> locked(mutex);
  auto previous=held;held=this;const auto result=f(o,a,b,c,d);held=previous;
  return result;
 }
};
class IOService:public OSObject {
public:
 IOWorkLoop *loop=nullptr;IOService *provider=nullptr;bool inactive=false;
 bool isInactive()const{return inactive;}
 IOService *getProvider()const{return provider;}
 IOWorkLoop *getWorkLoop()const{return loop;}
};
class IOCommandGate {
public:
 IOWorkLoop *loop=nullptr;bool enabled=true;
 IOWorkLoop *getWorkLoop()const{return loop;}
 bool isEnabled()const{return enabled;}
};
struct IOExternalMethodArguments {
 uint32_t version=2,selector=2;
 mach_port_t asyncWakePort=nullptr;
 uint64_t *asyncReference=nullptr;uint32_t asyncReferenceCount=0;
 const uint64_t *scalarInput=nullptr;uint32_t scalarInputCount=0;
 const void *structureInput=nullptr;uint32_t structureInputSize=0;
 void *structureInputDescriptor=nullptr;
 uint64_t *scalarOutput=nullptr;uint32_t scalarOutputCount=0;
 void *structureOutput=nullptr;uint32_t structureOutputSize=0;
 void *structureOutputDescriptor=nullptr;uint32_t structureOutputDescriptorSize=0;
 void *structureVariableOutputData=nullptr;
};
class IOUserClient:public IOService {
protected:
 static IOReturn sendAsyncResult64(OSAsyncReference64,IOReturn,uint64_t *,uint32_t);
public:
 std::atomic<int> refs{1};
 void retain(){++refs;}
 void release(){assert(!loop->inGate()&&refs>1);--refs;}
 static IOReturn releaseAsyncReference64(OSAsyncReference64);
};
class IOMemoryDescriptor {
public:
 unsigned refs=1;
 virtual ~IOMemoryDescriptor()=default;
 void retain(){++refs;++Control::retains;}
 void release(){++Control::releases;if(!--refs)delete this;}
};
class IOBufferMemoryDescriptor:public IOMemoryDescriptor {
 void *bytes=nullptr;size_t capacity,length;
public:
 explicit IOBufferMemoryDescriptor(size_t n):capacity(n),length(n){
  assert(!posix_memalign(&bytes,4096,n));memset(bytes,0xa5,n);++Control::alive;
 }
 ~IOBufferMemoryDescriptor()override{free(bytes);--Control::alive;}
 static IOBufferMemoryDescriptor *inTaskWithOptions(task_t task,IOOptionBits options,
                                                   size_t n,size_t alignment){
  assert(task==kernel_task&&options==(kIOMemoryKernelUserShared|kIODirectionInOut)&&alignment==4096);
  const auto index=++Control::allocations;
  if(Control::onAllocation)Control::onAllocation();
  if(index==Control::failAllocation)return nullptr;
  auto *result=new IOBufferMemoryDescriptor(n);
  // Each successful cycle allocates ring then state; later cycles must not
  // keep observing the first generation's separately retained mappings.
  if(index&1)Control::ring=result;else Control::state=result;
  return result;
 }
 void *getBytesNoCopy(){return bytes;}
 size_t getCapacity()const{return capacity;}
 size_t getLength()const{return length;}
 void setLength(size_t n){length=n;}
};
inline task_t current_task(){return Control::task;}
inline bool ml_at_interrupt_context(){return Control::interrupt;}
inline bool ml_get_interrupts_enabled(){return Control::interruptsEnabled;}
inline void clock_get_calendar_microtime(clock_sec_t *s,clock_usec_t *u){
 ++Control::clockCalls;*s=Control::seconds;*u=Control::microseconds;
}
// Explicit deferred thread-call and IRQ-lock model. This executes the real
// worker, but is not evidence of XNU scheduling or interrupt-context behavior.
using boolean_t=bool;
using IOInterruptState=bool;
struct IOSimpleLock {std::mutex mutex;};
inline std::vector<std::unique_ptr<IOSimpleLock>> &modelLocks(){
 static std::vector<std::unique_ptr<IOSimpleLock>> locks;return locks;
}
inline IOSimpleLock *IOSimpleLockAlloc(){
 auto &locks=modelLocks();locks.emplace_back(new IOSimpleLock);return locks.back().get();
}
inline void IOSimpleLockFree(IOSimpleLock *p){
 auto &locks=modelLocks();
 for(auto i=locks.begin();i!=locks.end();++i)if(i->get()==p){locks.erase(i);return;}
 abort();
}
inline IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *p){
 p->mutex.lock();const bool before=Control::interruptsEnabled;Control::interruptsEnabled=false;return before;
}
inline void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *p,IOInterruptState before){
 Control::interruptsEnabled=before;p->mutex.unlock();
}
using thread_call_param_t=void *;
using thread_call_func_t=void(*)(thread_call_param_t,thread_call_param_t);
struct ModelThreadCall {thread_call_func_t function;void *owner;bool pending=false,running=false;};
using thread_call_t=ModelThreadCall *;
enum {THREAD_CALL_PRIORITY_KERNEL=1,THREAD_CALL_OPTIONS_ONCE=2};
// Inline function-local statics are shared by every compiled component TU.
inline std::vector<std::unique_ptr<ModelThreadCall>> &modelCalls(){
 static std::vector<std::unique_ptr<ModelThreadCall>> calls;return calls;
}
inline thread_call_t thread_call_allocate_with_options(thread_call_func_t f,void *o,int p,int flags){
 assert(Control::interruptsEnabled&&p==THREAD_CALL_PRIORITY_KERNEL&&flags==THREAD_CALL_OPTIONS_ONCE);
 auto &calls=modelCalls();calls.emplace_back(new ModelThreadCall{f,o,false,false});return calls.back().get();
}
inline bool thread_call_enter(thread_call_t c){assert(!Control::interruptsEnabled);bool previous=c->pending;c->pending=true;return previous;}
inline bool thread_call_cancel(thread_call_t c){assert(!Control::interruptsEnabled);bool previous=c->pending;c->pending=false;return previous;}
inline void modelPump(){
 for(auto &entry:modelCalls()){
  auto *c=entry.get();if(!c->pending)continue;
  assert(!c->running);c->pending=false;c->running=true;c->function(c->owner,nullptr);c->running=false;
 }
}
'''

DEPENDENCIES = r'''
#pragma once
#include "mock.hpp"
#include "legacy_post_observer_core.hpp"
namespace AWDLKernel {
struct VersionCall {};
class DriverVersionBackend {
public:
 bool identity=true;
 mutable unsigned checks=0;
 bool matchesProviderIdentity(IOService *c,IOService *p)const{
  assert(c&&p&&c->getWorkLoop()->inGate());++checks;return identity;
 }
};
enum class ClientStatus:uint32_t {Passed,Argument};
class ClientRegistry;
class ClientWorkLease {
public:
 ClientRegistry *registry=nullptr;
 ~ClientWorkLease(){release();}
 ClientStatus release();
 uint64_t generation()const{return registry?7:0;}
 IOUserClient *client()const;
 task_t owner()const;
 IOService *provider()const;
 IOService *controller()const;
 IOCommandGate *gate()const;
 IOWorkLoop *workLoop()const;
};
class ClientRegistry {
public:
 IOUserClient *client=nullptr;IOService *provider=nullptr,*controller=nullptr;
 IOCommandGate *gate=nullptr;IOWorkLoop *loop=nullptr;
 task_t task=reinterpret_cast<task_t>(uintptr_t(2));bool open=true;
 ClientStatus acquire(IOUserClient *c,ClientWorkLease &out){
  assert(!out.registry);if(!open||c!=client)return ClientStatus::Argument;
  out.registry=this;++Control::ownerLeases;return ClientStatus::Passed;
 }
 ClientStatus acquireClosing(IOUserClient *c,ClientWorkLease &out){
  assert(!out.registry);if(c!=client)return ClientStatus::Argument;
  out.registry=this;++Control::ownerLeases;return ClientStatus::Passed;
 }
};
inline ClientStatus ClientWorkLease::release(){if(registry){--Control::ownerLeases;registry=nullptr;}return ClientStatus::Passed;}
inline IOUserClient *ClientWorkLease::client()const{return registry?registry->client:nullptr;}
inline task_t ClientWorkLease::owner()const{return registry?registry->task:nullptr;}
inline IOService *ClientWorkLease::provider()const{return registry?registry->provider:nullptr;}
inline IOService *ClientWorkLease::controller()const{return registry?registry->controller:nullptr;}
inline IOCommandGate *ClientWorkLease::gate()const{return registry?registry->gate:nullptr;}
inline IOWorkLoop *ClientWorkLease::workLoop()const{return registry?registry->loop:nullptr;}
namespace LegacyPostObserver {
enum class Status:uint32_t {Passed,Empty,Busy,Rejected};
struct AdmissionResult {Status status=Status::Passed;};
struct ObserverFixture {
 static bool admitted,closing,reject;
 static EventPipeWorker *worker;
 static unsigned copying;
 static LegacyPostObserverCore core;
 static ObserverHandle handle;
 static ObserverBinding binding;
};
class DeliveryLease {
 friend Status take(const ObserverHandle &,OwnedPostEvent &,DeliveryLease &);
 ObserverDelivery token{};
public:
 ~DeliveryLease(){if(token.sequence){assert(ObserverFixture::core.finish(token)==ObserverCoreStatus::Passed);--Control::deliveries;}}
};
inline AdmissionResult subscribe(ClientRegistry &r,IOUserClient *c,const DriverVersionBackend &,
                                  const VersionCall &,ObserverHandle &out){
 assert(r.loop->inGate()&&c==r.client);
 if(ObserverFixture::reject)return {Status::Rejected};
 size_t index=0;
 ObserverFixture::binding={reinterpret_cast<uintptr_t>(c),reinterpret_cast<uintptr_t>(r.provider),
  reinterpret_cast<uintptr_t>(r.controller),7};
 auto reserved=ObserverFixture::core.reserve(ObserverFixture::binding,index,out);
 EventPipeWorker *old=nullptr;bool reopening=false;
 if(reserved==ObserverCoreStatus::Duplicate){
  reserved=ObserverFixture::core.reserveReopen(ObserverFixture::binding,index,out,old);
  reopening=reserved==ObserverCoreStatus::Passed;
 }
 if(reserved!=ObserverCoreStatus::Passed)return {Status::Rejected};
 if(reopening && (!old || !old->canReplaceBinding())){
  assert(ObserverFixture::core.cancelReopen(out)==ObserverCoreStatus::Passed);
  return {Status::Rejected};
 }
 const auto activated=reopening?ObserverFixture::core.activateReopen(out,old):
  ObserverFixture::core.activate(out);
 if(activated!=ObserverCoreStatus::Passed)return {Status::Rejected};
 ObserverFixture::handle=out;ObserverFixture::admitted=true;
 if(Control::onSubscribe)Control::onSubscribe();return {};
}
inline Status beginClose(IOUserClient *client,ObserverHandle &out){
 ++Control::observerClosed;ObserverFixture::closing=true;
 return ObserverFixture::core.beginCloseClient(reinterpret_cast<uintptr_t>(client),out)==ObserverCoreStatus::Passed
  ?Status::Passed:Status::Rejected;
}
inline Status bindWorker(const ObserverHandle &handle,EventPipeWorker &worker){
 assert(worker.matchesBinding(handle));
 if(ObserverFixture::core.bindWorker(handle,&worker)!=ObserverCoreStatus::Passed)return Status::Rejected;
 ObserverFixture::worker=ObserverFixture::core.worker(handle);assert(ObserverFixture::worker==&worker);
 return Status::Passed;
}
inline Status beginCloseProvider(IOService *p,ObserverHandle &out){
 return ObserverFixture::core.beginCloseProvider(reinterpret_cast<uintptr_t>(p),out)==ObserverCoreStatus::Passed
  ?Status::Passed:Status::Rejected;
}
inline size_t beginCloseController(IOService *c){
 return ObserverFixture::core.beginCloseController(reinterpret_cast<uintptr_t>(c));
}
inline Status pollDrain(const ObserverHandle &handle,ObserverDrain &out){
 auto result=ObserverFixture::core.drain(handle,out);out.copying+=ObserverFixture::copying;
 return result==ObserverCoreStatus::Passed&&!out.copying?Status::Passed:Status::Busy;
}
inline Status take(const ObserverHandle &handle,OwnedPostEvent &out,DeliveryLease &delivery){
 auto result=ObserverFixture::core.take(handle,out,delivery.token);
 if(result==ObserverCoreStatus::Passed){++Control::deliveries;if(Control::onTake)Control::onTake();return Status::Passed;}
 return result==ObserverCoreStatus::Empty?Status::Empty:Status::Rejected;
}
}
}
'''

HARNESS = r'''
#include "event_pipe_session.hpp"
#include "event_pipe_router.hpp"
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
#include "baseline_trace.hpp"
#endif
#include <thread>
#include <vector>
using namespace AWDLKernel;
thread_local bool Control::interrupt=false,Control::interruptsEnabled=true;
thread_local task_t Control::task=reinterpret_cast<task_t>(uintptr_t(2));
thread_local IOWorkLoop *IOWorkLoop::held=nullptr;
#define COUNTER(n) std::atomic<int> Control::n{0}
COUNTER(allocations);COUNTER(alive);COUNTER(retains);COUNTER(releases);COUNTER(rights);
COUNTER(migCleanup);COUNTER(sends);COUNTER(rightReleases);COUNTER(deliveries);
COUNTER(ownerLeases);COUNTER(clockCalls);COUNTER(observerClosed);
#undef COUNTER
int Control::failAllocation=0,Control::failSend=0;
clock_usec_t Control::microseconds=123456;
clock_sec_t Control::seconds=UINT64_C(0x100000002);
uint64_t Control::expectedReference=0x1001;
void (*Control::onAllocation)()=nullptr;void (*Control::onSubscribe)()=nullptr;
void (*Control::onTake)()=nullptr;void (*Control::onBeforeAction)()=nullptr;
void (*Control::onSend)()=nullptr;
IOMemoryDescriptor *Control::ring=nullptr,*Control::state=nullptr;
bool LegacyPostObserver::ObserverFixture::admitted=false;
bool LegacyPostObserver::ObserverFixture::closing=false;
bool LegacyPostObserver::ObserverFixture::reject=false;
EventPipeWorker *LegacyPostObserver::ObserverFixture::worker=nullptr;
unsigned LegacyPostObserver::ObserverFixture::copying=0;
LegacyPostObserverCore LegacyPostObserver::ObserverFixture::core;
ObserverHandle LegacyPostObserver::ObserverFixture::handle{};
ObserverBinding LegacyPostObserver::ObserverFixture::binding{};
static uint32_t word(const void *p){uint32_t v;memcpy(&v,p,4);return v;}
static uint64_t qword(const void *p){uint64_t v;memcpy(&v,p,8);return v;}
static void *bytes(IOMemoryDescriptor *p){return static_cast<IOBufferMemoryDescriptor *>(p)->getBytesNoCopy();}
static EventPipeSession *current=nullptr;
static IOWorkLoop *currentLoop=nullptr;
static IOUserClient *currentClient=nullptr;
IOReturn IOUserClient::sendAsyncResult64(OSAsyncReference64 ref,IOReturn result,uint64_t *args,uint32_t count){
 assert(!currentLoop->inGate()&&!Control::interrupt&&Control::interruptsEnabled);
 assert(Control::rights==1&&ref[0]==Control::expectedReference&&result==0&&!args&&!count);
 // Router deliberately hides its Session. Check actual delivery+notification
 // object refs, not an invented bool authorizing a fake Session operation.
 assert(Control::deliveries==1&&currentClient&&currentClient->refs>=3&&Control::alive>=2);
 if(current)assert(current->operations()>0);
 auto *ring=static_cast<uint8_t *>(bytes(Control::ring));
 auto *state=static_cast<awc_ring_shared *>(bytes(Control::state));
 assert(state->write_offset>0&&word(ring)==0x57); // Commit precedes zero-arg send.
 ++Control::sends;if(Control::onSend)Control::onSend();return Control::failSend;
}
IOReturn IOUserClient::releaseAsyncReference64(OSAsyncReference64 ref){
 assert(!currentLoop->inGate()&&Control::rights==1&&ref[0]==Control::expectedReference);
 assert(!Control::deliveries);--Control::rights;++Control::rightReleases;return 0;
}
struct Fixture {
 IOWorkLoop loop;IOCommandGate gate;IOService controller,provider;IOUserClient client;
 ClientRegistry registry;DriverVersionBackend backend;VersionCall version;EventPipeSession pipe;
 uint64_t refs[8]{0x1001,2,3,4,5,6,7,8};IOExternalMethodArguments args;
 Fixture(){
  gate.loop=&loop;controller.loop=&loop;provider.loop=&loop;provider.provider=&controller;
  client.loop=&loop;client.provider=&provider;
  registry.client=&client;registry.provider=&provider;registry.controller=&controller;
  registry.gate=&gate;registry.loop=&loop;
  args.asyncWakePort=reinterpret_cast<void *>(uintptr_t(0x1000));args.asyncReference=refs;args.asyncReferenceCount=8;
  current=&pipe;currentLoop=&loop;currentClient=&client;Control::expectedReference=refs[0];
 }
 IOReturn create(){return pipe.create(registry,&client,backend,version);}
 static IOReturn rpcAction(OSObject *,void *p,void *,void *,void *){
  auto &f=*static_cast<Fixture *>(p);return f.pipe.subscribeFromSuccessfulDispatch(f.args);
 }
 IOReturn rpc(){
  ++Control::rights;
  const auto result=loop.runAction(rpcAction,&client,this);
  // This is the actual documented MIG ownership boundary: no post-success check.
  if(result){--Control::rights;++Control::migCleanup;}
  return result;
 }
 void open(){assert(!create());assert(!rpc());}
 void queue(uint32_t message=46){
  ObserverCapture token;ObserverBinding binding;uint8_t body[68]{};body[8]=1;
  assert(LegacyPostObserver::ObserverFixture::core.begin(reinterpret_cast<uintptr_t>(&provider),
   message==46?0xb3824:0x42c7a,message,message==46?nullptr:body,message==46?0:68,token,binding)==ObserverCoreStatus::Passed);
  if(message==47)memcpy(LegacyPostObserver::ObserverFixture::core.buffer(token),body,68);
  assert(LegacyPostObserver::ObserverFixture::core.commit(token)==ObserverCoreStatus::Passed);
  auto *worker=LegacyPostObserver::ObserverFixture::core.worker(token.owner);assert(worker);
  (void)worker->kickFromProducer(token.owner);
 }
 void frame(const std::vector<uint8_t> &body){
  ObserverCapture token;ObserverBinding binding;
  assert(LegacyPostObserver::ObserverFixture::core.begin(reinterpret_cast<uintptr_t>(&provider),
   0x3f20d,48,body.data(),body.size(),token,binding)==ObserverCoreStatus::Passed);
  memcpy(LegacyPostObserver::ObserverFixture::core.buffer(token),body.data(),body.size());
  assert(LegacyPostObserver::ObserverFixture::core.commit(token)==ObserverCoreStatus::Passed);
  auto *worker=LegacyPostObserver::ObserverFixture::core.worker(token.owner);assert(worker);
  (void)worker->kickFromProducer(token.owner);
 }
 void close(){assert(!pipe.close());assert(pipe.phase()==EventPipeCore::Phase::Closed);}
 ~Fixture(){assert(!Control::alive&&!Control::rights&&!Control::ownerLeases&&!Control::deliveries);
  assert(client.refs==1&&loop.refs==1);}
};
// Reuse only identity/queue helpers. The base pipe is unused in these cases:
// ALL create/map/subscribe/close calls below execute the actual Router, whose
// internal resident Sessions are deliberately not exposed to this fixture.
struct RouterFixture:Fixture {
 EventPipeRouter router;unsigned subscriptions=0;
 RouterFixture(){
  current=nullptr;assert(!router.ready());assert(!router.prepare(registry,backend));assert(router.ready());
 }
 IOReturn create(){return router.create(&client,version);}
 static IOReturn rpcAction(OSObject *,void *p,void *,void *,void *){
  auto &f=*static_cast<RouterFixture *>(p);return f.router.subscribeFromSuccessfulDispatch(&f.client,f.args);
 }
 IOReturn rpc(){
  assert(!Control::rights);refs[0]=0x2001+16*subscriptions++;
  args.asyncWakePort=reinterpret_cast<void *>(uintptr_t(refs[0]&~3ULL));
  Control::expectedReference=refs[0];++Control::rights;
  const auto result=loop.runAction(rpcAction,&client,this);
  if(result){--Control::rights;++Control::migCleanup;}
  return result;
 }
 void open(){assert(!create());assert(!rpc());}
 IOReturn halt(){return router.destroy(&client);}
 void close(){assert(!halt());assert(!Control::rights);}
 void maps(IOMemoryDescriptor *&ring,IOMemoryDescriptor *&state){
  IOOptionBits options=99;
  assert(!router.retainMemoryForType(&client,1,&options,&ring)&&options==kIOMapReadOnly);
  assert(!router.retainMemoryForType(&client,2,&options,&state)&&options==0);
 }
};
static std::vector<uint8_t> frame48(){
 std::vector<uint8_t> frame(94,0);frame[0]=2;frame[12]=1;frame[16]=6;frame[20]=0xa; // Actual2GHz20MHz.
 const uint8_t header[]={0x7f,0,0x17,0xf2,8,0x10,3,0};memcpy(frame.data()+72,header,sizeof(header));
 frame[88]=0xfe;frame[89]=3;frame[91]=9;frame[92]=8;frame[93]=7;return frame;
}
static std::atomic<bool> entered{false},resume{false};
static void pauseHook(){entered=true;while(!resume.load())std::this_thread::yield();}
static void closeWhileOperation(){
 assert(current->operations()>0);current->beginClose();assert(current->close()==kIOReturnBusy);
 assert(Control::alive==2);
}
static void test(int n){
 if(n==0){
  Fixture f;f.open();IOMemoryDescriptor *ring=nullptr,*state=nullptr;IOOptionBits options=99;
  assert(!f.pipe.retainMemoryForType(1,&options,&ring)&&options==kIOMapReadOnly&&ring->refs==2);
  assert(!f.pipe.retainMemoryForType(2,&options,&state)&&options==0&&state->refs==2);
  f.queue(47);auto result=f.pipe.drainOne();assert(!result.result&&!result.notification&&result.committed&&!result.dropped);
  auto *record=static_cast<uint8_t *>(bytes(ring));
  assert(qword(record+8)==Control::seconds&&qword(record+16)==Control::microseconds);
  uint8_t expected[16]={'a','w','d','l','0'};assert(!memcmp(record+32,expected,16));
  assert(word(record+28)==47&&word(record+48+8)==1&&Control::sends==1);
  f.close();assert(Control::alive==2&&ring->refs==1&&state->refs==1&&word(record)==0x57);
  ring->release();state->release();assert(Control::rightReleases==1);
 }else if(n==1||n==2){
  Fixture f;Control::failAllocation=n;assert(f.create()==kIOReturnNoMemory);
  assert(!Control::alive&&!Control::ownerLeases&&!LegacyPostObserver::ObserverFixture::admitted);
  f.close();assert(!Control::rightReleases);
 }else if(n==3||n==4){
  Fixture f;if(n==3)Control::onAllocation=pauseHook;else Control::onSubscribe=pauseHook;
  IOReturn result=0;std::thread creator([&]{result=f.create();});
  while(!entered.load())std::this_thread::yield();assert(f.pipe.close()==kIOReturnBusy);
  assert(f.pipe.phase()==EventPipeCore::Phase::Closing);
  if(n==4)assert(Control::alive==2&&!Control::observerClosed);
  resume=true;creator.join();Control::onAllocation=Control::onSubscribe=nullptr;
  assert(result!=0&&f.pipe.phase()==EventPipeCore::Phase::Closed&&!Control::alive);
  if(n==4)assert(Control::observerClosed==1);
 }else if(n==5){
  Fixture f;assert(!f.create());IOMemoryDescriptor *md=reinterpret_cast<IOMemoryDescriptor *>(uintptr_t(1));IOOptionBits options=99;
  Control::onBeforeAction=closeWhileOperation;
  assert(f.pipe.retainMemoryForType(1,&options,&md)==kIOReturnNotReady&&!md&&!options);
  assert(!Control::retains);f.close();
 }else if(n==6){
  Fixture f;assert(!f.create());f.args.asyncReferenceCount=7;
  assert(f.rpc()==kIOReturnBadArgument&&!Control::rights&&Control::migCleanup==1&&!Control::rightReleases);
  f.args.asyncReferenceCount=8;assert(!f.rpc()&&Control::rights==1);
  assert(f.rpc()==kIOReturnBusy&&Control::rights==1&&Control::migCleanup==2);
  f.close();assert(Control::rightReleases==1);
 }else if(n==7){
  Fixture f;f.open();f.queue();Control::onTake=closeWhileOperation;
  auto result=f.pipe.drainOne();Control::onTake=nullptr;
  assert(result.result==kIOReturnNotReady&&result.dropped&&!result.committed&&!Control::sends&&!Control::clockCalls);
  assert(!Control::deliveries);f.close();
 }else if(n==8||n==9){
  Fixture f;f.open();f.queue();Control::onSend=pauseHook;
  EventPipeSession::PublishResult result;
  std::thread publisher([&]{result=f.pipe.drainOne();});
  while(!entered.load())std::this_thread::yield();
  assert(f.pipe.operations()==1&&Control::deliveries==1&&Control::rights==1);
  assert(f.pipe.drainOne().result==kIOReturnBusy&&f.pipe.operations()==1);
  assert(f.pipe.close()==kIOReturnBusy&&!Control::rightReleases&&Control::alive==2);
  resume=true;publisher.join();Control::onSend=nullptr;
  assert(!result.result&&!result.notification&&result.committed&&!Control::deliveries);
  f.close();assert(Control::rightReleases==1);
 }else if(n==10){
  Fixture f;f.open();f.queue();LegacyPostObserver::ObserverFixture::copying=1;
  assert(f.pipe.close()==kIOReturnBusy&&Control::alive==2&&Control::rights==1&&!Control::rightReleases);
  assert(f.pipe.drainOne().result==kIOReturnNotReady); // Closed admission, queued snapshot canceled.
  ObserverDrain drained;LegacyPostObserver::ObserverFixture::core.drain(LegacyPostObserver::ObserverFixture::handle,drained);
  assert(!drained.queued);LegacyPostObserver::ObserverFixture::copying=0;f.close();
 }else if(n==11||n==12){
  Fixture f;f.open();f.queue();
  if(n==11)f.backend.identity=false;else Control::microseconds=1000000;
  auto result=f.pipe.drainOne();assert(result.result!=0&&result.dropped&&!result.committed&&!Control::sends);
  assert(!Control::deliveries&&word(bytes(Control::ring))==0);
  if(n==11)assert(!Control::clockCalls);f.close();
 }else if(n==13){
  Fixture f;f.open();f.queue();Control::failSend=kIOReturnAborted;
  auto result=f.pipe.drainOne();assert(!result.result&&result.notification==kIOReturnAborted&&result.committed);
  assert(f.pipe.drainOne().result==kIOReturnNotFound&&Control::sends==1);f.close();
 }else if(n==14){
  Fixture f;f.open();for(int i=0;i<170;++i){f.queue();assert(f.pipe.drainOne().committed);}
  std::vector<uint8_t> before(8192);memcpy(before.data(),bytes(Control::ring),8192);
  f.queue();auto result=f.pipe.drainOne();assert(!result.result&&!result.notification&&result.full&&result.dropped&&!result.committed);
  assert(!memcmp(before.data(),bytes(Control::ring),8192)&&Control::sends==171);f.close();
 }else if(n==15){
  Fixture f;f.pipe.beginClose();f.close();assert(f.create()==kIOReturnBusy&&!Control::allocations);
 }else if(n==16){
  Fixture f;LegacyPostObserver::ObserverFixture::reject=true;
  assert(f.create()==kIOReturnNotReady&&!Control::alive&&!Control::ownerLeases);
  assert(!Control::rightReleases);f.close();
 }else if(n==17){
  Fixture f;assert(!f.create());Control::task=reinterpret_cast<task_t>(uintptr_t(3));
  assert(f.rpc()==kIOReturnNotPrivileged&&Control::migCleanup==1&&!Control::rights);
  IOMemoryDescriptor *md=nullptr;IOOptionBits options=0;
  assert(f.pipe.retainMemoryForType(1,&options,&md)==kIOReturnNotPrivileged&&!md);
  Control::task=reinterpret_cast<task_t>(uintptr_t(2));f.close();
 }else if(n>=18&&n<=20){
  Fixture f;f.open();
  const size_t size=n==20?AWCM48_MAX_BODY:94;
  std::vector<uint8_t> frame(size,0);
  frame[0]=2;frame[12]=1;frame[16]=6;frame[20]=0xa;
  const uint8_t header[]={0x7f,0,0x17,0xf2,8,0x10,3,0};
  memcpy(frame.data()+72,header,sizeof(header));
  frame[88]=0xfe;const uint16_t length=static_cast<uint16_t>(size-91);
  frame[89]=static_cast<uint8_t>(length);frame[90]=static_cast<uint8_t>(length>>8);
  for(size_t i=91;i<size;++i)frame[i]=static_cast<uint8_t>(i);
  if(n==19)++frame[89]; // Incomplete final TLV is captured, then rejected by the codec.
  f.frame(frame);auto result=f.pipe.drainOne();
  if(n==19){
   assert(result.result==kIOReturnUnsupported&&result.dropped&&!result.committed);
   assert(result.codecAttempted==1&&result.codecError==AWCM_LENGTH&&
          result.codecRejectMask==AWCM48_REJECT_TLV_LENGTH);
   assert(!Control::clockCalls&&!Control::sends&&!word(bytes(Control::ring)));
  }else{
   assert(!result.result&&!result.notification&&result.committed&&result.message==48);
   assert(result.codecAttempted==1&&result.codecError==AWCM_OK&&!result.codecRejectMask);
   auto *record=static_cast<uint8_t *>(bytes(Control::ring));
   assert(word(record+28)==48&&!memcmp(record+48,frame.data(),size)&&Control::sends==1);
  }
  assert(!Control::deliveries);f.close();
 }else if(n==21){
  Fixture f;assert(!f.create());f.queue();
  auto waiting=f.pipe.drainOne();
  assert(waiting.result==kIOReturnNotReady&&!waiting.dropped&&!Control::deliveries&&!Control::sends);
  assert(!f.rpc());auto result=f.pipe.drainOne();
  assert(!result.result&&result.committed&&Control::sends==1);f.close();
 }else if(n==22){
  Fixture f;f.open();f.queue(47);modelPump();
  auto snapshot=f.pipe.workerSnapshot();
  assert(snapshot.callbacks==1&&snapshot.committed==1&&snapshot.empty==1);
  assert(!snapshot.queued&&!snapshot.running&&Control::sends==1);
  f.close();assert(f.pipe.workerSnapshot().state==EventPipeWorker::State::Stopped);
 }else if(n==23){
  Fixture f;f.open();f.queue(47);Control::onSend=pauseHook;
  std::thread consumer([]{modelPump();});
  while(!entered.load())std::this_thread::yield();
  assert(f.pipe.workerSnapshot().running==1&&f.pipe.operations()==1);
  assert(f.pipe.close()==kIOReturnBusy&&Control::alive==2&&Control::rights==1);
  resume=true;consumer.join();Control::onSend=nullptr;
  f.close();assert(Control::rightReleases==1&&f.pipe.workerSnapshot().state==EventPipeWorker::State::Stopped);
 }else if(n==24){
  Fixture f;f.open();f.queue();Control::failSend=kIOReturnAborted;modelPump();
  auto snapshot=f.pipe.workerSnapshot();
  assert(snapshot.faults==1&&snapshot.committed==1&&Control::sends==1);
  assert(f.pipe.phase()==EventPipeCore::Phase::Closing);
  modelPump();assert(Control::sends==1);f.close();
 }else if(n==25){
  RouterFixture f;f.open();IOMemoryDescriptor *oldRing=nullptr,*oldState=nullptr;f.maps(oldRing,oldState);
  const auto handle=LegacyPostObserver::ObserverFixture::handle;
  auto *oldWorker=LegacyPostObserver::ObserverFixture::core.worker(handle);assert(oldWorker);
  auto frame=frame48();f.frame(frame);modelPump();
  assert(Control::sends==1&&word(static_cast<uint8_t *>(bytes(oldRing))+28)==48);
  std::vector<uint8_t> before(8192);memcpy(before.data(),bytes(oldRing),8192);
  assert(!f.halt()&&f.registry.open&&f.router.ready()&&oldWorker->canReplaceBinding());
  assert(Control::alive==2&&oldRing->refs==1&&oldState->refs==1&&Control::rightReleases==1);
  f.open();IOMemoryDescriptor *newRing=nullptr,*newState=nullptr;f.maps(newRing,newState);
  assert(newRing!=oldRing&&newState!=oldState&&Control::ring==newRing&&Control::state==newState);
  auto *newWorker=LegacyPostObserver::ObserverFixture::core.worker(handle);
  assert(newWorker&&newWorker!=oldWorker&&!newWorker->canReplaceBinding());
  assert(LegacyPostObserver::ObserverFixture::handle.client==handle.client&&
         LegacyPostObserver::ObserverFixture::handle.generation==handle.generation);
  f.frame(frame);modelPump();assert(Control::sends==2&&!memcmp(before.data(),bytes(oldRing),8192));
  auto snapshot=f.router.snapshot();assert(snapshot.used==2&&snapshot.live==1&&snapshot.terminal==1);
  assert(snapshot.workerCommitted==2&&!snapshot.retiring&&f.registry.open);
  f.close();assert(Control::rightReleases==2&&Control::alive==4);
  oldRing->release();oldState->release();newRing->release();newState->release();
 }else if(n==26){
  RouterFixture f;f.open();f.queue(47);Control::onSend=pauseHook;
  std::thread consumer([]{modelPump();});while(!entered.load())std::this_thread::yield();
  assert(f.router.snapshot().workerRunning==1&&Control::deliveries==1);
  assert(f.halt()==kIOReturnBusy&&Control::rights==1&&Control::alive==2);
  assert(f.create()==kIOReturnBusy&&f.router.snapshot().used==1&&Control::allocations==2);
  assert(f.registry.open&&!f.router.snapshot().retiring);
  resume=true;consumer.join();Control::onSend=nullptr;
  // No second Halt: the later selector3 itself completes old close and retries.
  assert(!f.create()&&!Control::rights&&Control::rightReleases==1&&Control::allocations==4);
  assert(!f.rpc());f.queue();modelPump();assert(Control::sends==2);
  assert(f.router.snapshot().used==2&&f.router.snapshot().terminal==1);f.close();
 }else if(n==27){
  RouterFixture f;f.open();auto &oldCall=*modelCalls().front();
  f.queue();modelPump();assert(Control::sends==1);
  ObserverCapture first;ObserverBinding bound;
  assert(LegacyPostObserver::ObserverFixture::core.begin(reinterpret_cast<uintptr_t>(&f.provider),
   0xb3824,46,nullptr,0,first,bound)==ObserverCoreStatus::Passed);
  assert(LegacyPostObserver::ObserverFixture::core.commit(first)==ObserverCoreStatus::Passed);
  auto *oldWorker=LegacyPostObserver::ObserverFixture::core.worker(first.owner);assert(oldWorker);
  (void)oldWorker->kickFromProducer(first.owner);
  assert(oldCall.pending&&!oldCall.running);oldCall.pending=false;oldCall.running=true;
  assert(f.halt()==kIOReturnBusy&&f.create()==kIOReturnBusy&&!oldWorker->canReplaceBinding());
  oldCall.function(oldCall.owner,nullptr);oldCall.running=false; // Late Closing callback, no take.
  assert(!f.create()&&oldWorker->canReplaceBinding());assert(!f.rpc());
  ObserverCapture newer;assert(LegacyPostObserver::ObserverFixture::core.begin(
   reinterpret_cast<uintptr_t>(&f.provider),0xb3824,46,nullptr,0,newer,bound)==ObserverCoreStatus::Passed);
  assert(newer.sequence>first.sequence&&newer.owner.generation==first.owner.generation);
  assert(LegacyPostObserver::ObserverFixture::core.commit(newer)==ObserverCoreStatus::Passed);
  auto *newWorker=LegacyPostObserver::ObserverFixture::core.worker(newer.owner);assert(newWorker!=oldWorker);
  (void)newWorker->kickFromProducer(newer.owner);
  // A synthetic delayed entry still targets old immutable Session; it cannot
  // lookup the new same-handle observer or send the NEW adopted reference.
  oldCall.function(oldCall.owner,nullptr);
  assert(Control::sends==1&&word(bytes(Control::ring))==0);
  modelPump();assert(Control::sends==2&&f.router.snapshot().workerCommitted==2);
  f.close();assert(Control::rightReleases==2);
 }else if(n==28){
  RouterFixture f;
  for(unsigned cycle=0;cycle<EventPipeRouter::MaximumSessions;++cycle){
   f.open();IOMemoryDescriptor *ring=nullptr,*state=nullptr;f.maps(ring,state);
   f.queue();modelPump();assert(Control::sends==static_cast<int>(cycle+1));
   assert(!f.halt()&&f.registry.open&&!Control::rights);
   ring->release();state->release();assert(!Control::alive);
  }
  const auto before=Control::allocations.load();
  assert(f.create()==kIOReturnNoResources&&Control::allocations==before&&f.registry.open);
  auto snapshot=f.router.snapshot();assert(snapshot.used==8&&snapshot.terminal==8&&!snapshot.live&&!snapshot.retiring&&f.router.ready());
  assert(snapshot.workerCommitted==8&&Control::rightReleases==8);
  ClientWorkLease controlLease;assert(f.registry.acquire(&f.client,controlLease)==ClientStatus::Passed);
  controlLease.release();assert(!f.halt()&&f.registry.open); // UC control registration survives budget exhaustion.
 }else if(n==29){
  RouterFixture f;f.open();f.queue();modelPump();
  f.router.markClientClosing(&f.client);f.registry.open=false;
  assert(f.router.snapshot().retiring&&!f.router.ready()&&f.halt()==kIOReturnNotReady);
  Control::task=reinterpret_cast<task_t>(uintptr_t(3)); // Trusted cleanup need not be owning task.
  assert(!f.router.collect(&f.client)&&!Control::rights&&!Control::alive);
  assert(f.router.snapshot().terminal==1&&Control::rightReleases==1);
  assert(f.create()==kIOReturnNotReady);Control::task=reinterpret_cast<task_t>(uintptr_t(2));
 }else if(n==30){
  RouterFixture f;f.open();f.queue(46);f.queue(47);auto valid=frame48();f.frame(valid);
  auto flags=valid;flags[20]=0xb;f.frame(flags); // Multiple width bits remain invalid.
  auto tlv=valid;tlv[89]++;f.frame(tlv);modelPump();
  auto s=f.router.snapshot();
  assert(s.received46==1&&s.received47==1&&s.received48==3&&!s.receivedOther);
  assert(!s.rejected46&&!s.rejected47&&s.rejected48==2&&!s.rejectedOther);
  assert(s.committed46==1&&s.committed47==1&&s.committed48==1&&!s.committedOther);
  assert(s.workerCommitted==3&&s.workerDropped==2&&!s.workerFull&&!s.workerFaults&&Control::sends==3);
  assert(s.lastCodecMessage==48&&s.lastCodecError==AWCM_LENGTH&&s.last48RejectMask==AWCM48_REJECT_TLV_LENGTH);
  assert(s.seen48RejectMask==(AWCM48_REJECT_CHANNEL_FLAGS|AWCM48_REJECT_TLV_LENGTH));
  // A genuine empty callback must not manufacture a fourth received48 or
  // replace the last diagnosed failure with its default-zero PublishResult.
  auto handle=LegacyPostObserver::ObserverFixture::handle;
  auto *worker=LegacyPostObserver::ObserverFixture::core.worker(handle);assert(worker);
  (void)worker->kickFromProducer(handle);modelPump();auto empty=f.router.snapshot();
  assert(empty.workerCallbacks==s.workerCallbacks+1&&empty.received48==3&&empty.rejected48==2);
  assert(empty.lastCodecMessage==s.lastCodecMessage&&empty.lastCodecError==s.lastCodecError&&
   empty.last48RejectMask==s.last48RejectMask&&empty.seen48RejectMask==s.seen48RejectMask);
  f.close();
 }else if(n==31){
  RouterFixture f;f.open();auto invalid=frame48();invalid[7]=1;f.frame(invalid);modelPump();
  auto first=f.router.snapshot();assert(first.rejected48==1&&first.last48RejectMask==AWCM48_REJECT_RESERVED6);
  assert(!f.halt());f.open();f.queue(46);modelPump();assert(!f.halt());
  f.open();modelPump(); // Newest allocated Session has only an empty callback.
  auto s=f.router.snapshot();assert(s.used==3&&s.terminal==2&&s.live==1);
  assert(s.received48==1&&s.rejected48==1&&s.received46==1&&s.committed46==1);
  assert(s.lastCodecMessage==46&&s.lastCodecError==AWCM_OK&&
   s.last48RejectMask==AWCM48_REJECT_RESERVED6&&s.seen48RejectMask==AWCM48_REJECT_RESERVED6);
  assert(s.workerCommitted==1&&s.workerDropped==1&&Control::sends==1);f.close();
 }else if(n==32){
  Fixture f;assert(!f.create());auto invalid=frame48();invalid[12]=0;f.frame(invalid);
  auto waiting=f.pipe.drainOne();assert(waiting.result==kIOReturnNotReady&&!waiting.codecAttempted&&
   !waiting.message&&!waiting.codecError&&!waiting.codecRejectMask);
  assert(!f.rpc());auto rejected=f.pipe.drainOne();
  assert(rejected.codecAttempted==1&&rejected.message==48&&rejected.codecError==AWCM_CONTENT&&
   rejected.codecRejectMask==AWCM48_REJECT_METADATA_VERSION&&rejected.result==kIOReturnUnsupported);
  auto empty=f.pipe.drainOne();assert(empty.result==kIOReturnNotFound&&!empty.codecAttempted&&
   !empty.message&&!empty.codecError&&!empty.codecRejectMask);
  f.queue(47);auto accepted=f.pipe.drainOne();assert(accepted.committed&&accepted.codecAttempted==1&&
   accepted.message==47&&accepted.codecError==AWCM_OK&&!accepted.codecRejectMask);
  f.close();
 }else if(n==33){
  RouterFixture f;f.open();
  // Source-derived20/40/80MHz values, not a claim of a live RF capture.
  // 40MHz tests both extension directions;80MHz tests optionalDFS unchanged.
  const uint32_t flags[]={0xa,0x12,0xc,0x20c,0x14,0x214,0x410,0x510};
  std::vector<std::vector<uint8_t>> expected;
  for(auto flag:flags){
   auto frame=frame48();memcpy(frame.data()+20,&flag,sizeof(flag));
   frame[16]=(flag&0x10)?((flag&0x100)?100:44):6;
   expected.push_back(frame);f.frame(frame);
  }
  modelPump();auto snapshot=f.router.snapshot();
  assert(snapshot.received48==8&&snapshot.committed48==8&&!snapshot.rejected48);
  assert(snapshot.workerCommitted==8&&!snapshot.workerDropped&&!snapshot.workerFull&&!snapshot.workerFaults);
  assert(snapshot.lastCodecMessage==48&&snapshot.lastCodecError==AWCM_OK&&
   !snapshot.last48RejectMask&&!snapshot.seen48RejectMask&&Control::sends==8);
  size_t offset=0;auto *ring=static_cast<uint8_t *>(bytes(Control::ring));
  for(const auto &frame:expected){
   assert(word(ring+offset)==0x57&&word(ring+offset+28)==48);
   uint16_t length=0;memcpy(&length,ring+offset+24,sizeof(length));assert(length==frame.size());
   assert(!memcmp(ring+offset+48,frame.data(),frame.size()));
   offset+=(48+frame.size()+3)&~size_t(3);
  }
  f.close();
 }else if(n==34){
  RouterFixture f;f.open();
  const uint32_t bad[]={0x1a,0xb,0x20a,0x812}; // Dualband/multiwidth/non40 extension/unknown bit.
  for(auto flags:bad){auto frame=frame48();memcpy(frame.data()+20,&flags,sizeof(flags));f.frame(frame);}
  modelPump();auto snapshot=f.router.snapshot();
  assert(snapshot.received48==4&&snapshot.rejected48==4&&!snapshot.committed48);
  assert(snapshot.workerDropped==4&&!snapshot.workerFaults&&!Control::sends&&!word(bytes(Control::ring)));
  assert(snapshot.lastCodecError==AWCM_CONTENT&&snapshot.last48RejectMask==AWCM48_REJECT_CHANNEL_FLAGS&&
   snapshot.seen48RejectMask==AWCM48_REJECT_CHANNEL_FLAGS);f.close();
 }else if(n==35){
  Fixture f;assert(!f.create());auto valid=frame48();f.frame(valid);assert(!f.rpc());
  const auto published=f.pipe.drainOne();
  assert(published.committed&&published.codecError==AWCM_OK&&published.message==48);
  const auto trace=BaselineTrace::snapshot();
  assert(trace.controlRxOnly==1&&trace.samplesReady==1&&trace.message48Samples==1);
  assert(trace.mifSamples==1&&trace.lastActionSubtype==3&&trace.lastLength==valid.size());
  f.close();
 }else abort();
}
int main(int argc,char **argv){assert(argc==2);test(atoi(argv[1]));}
'''


class EventPipeSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="event-pipe-session-", dir="/private/tmp")
        cls.folder = Path(cls.temporary.name)
        kernel = cls.folder / "src/awdl_kernel"
        compat = cls.folder / "src/awdl_compat"
        kernel.mkdir(parents=True)
        compat.mkdir()
        for name in ["event_pipe_session.hpp", "event_pipe_session.cpp", "event_pipe_core.hpp",
                     "event_memory.hpp", "event_memory.cpp", "async_notification_owner.hpp",
                     "async_notification_owner.cpp", "legacy_post_observer_core.hpp",
                     "event_pipe_worker.hpp", "event_pipe_worker.cpp",
                     "event_pipe_router.hpp", "event_pipe_router.cpp"]:
            shutil.copyfile(PROJECT / "src/awdl_kernel" / name, kernel / name)
        for name in ["baseline_trace.hpp", "baseline_trace.cpp"]:
            shutil.copyfile(PROJECT / "src/awdl_kernel" / name, kernel / name)
        for name in ["event_ring.h", "event_ring.c", "awdl_message_codec.h", "awdl_message_codec.c",
                     "message48_subset_codec.h", "message48_subset_codec.c"]:
            shutil.copyfile(PROJECT / "src/awdl_compat" / name, compat / name)
        (kernel / "legacy_post_observer.hpp").write_text(DEPENDENCIES)
        (cls.folder / "mock.hpp").write_text(MOCK)
        (cls.folder / "harness.cpp").write_text(HARNESS)
        for name in ["IOKit/IOUserClient.h", "IOKit/IOWorkLoop.h",
                     "IOKit/IOBufferMemoryDescriptor.h", "kern/task.h", "kern/clock.h",
                     "machine/machine_routines.h", "IOKit/IOLocks.h", "IOKit/IOReturn.h",
                     "kern/thread_call.h"]:
            path = cls.folder / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('#include "mock.hpp"\n')
        flags = ["-Wall", "-Wextra", "-Werror", "-DAIRPORT_BRCM_BASELINE_TRACE=1",
                 "-fsanitize=address,undefined",
                 "-fno-omit-frame-pointer", "-I", str(cls.folder), "-I", str(kernel)]
        objects = []
        for name in ["event_ring", "awdl_message_codec", "message48_subset_codec"]:
            obj = cls.folder / (name + ".o")
            cls.compile(["xcrun", "clang", "-std=c11", *flags, "-c",
                         str(compat / (name + ".c")), "-o", str(obj)])
            objects.append(str(obj))
        cls.binary = cls.folder / "composition"
        cls.compile(["xcrun", "clang++", "-std=c++14", "-pthread", *flags,
                     *[str(kernel / (name + ".cpp")) for name in
                       ["event_pipe_session", "event_memory", "async_notification_owner", "event_pipe_worker",
                        "event_pipe_router", "baseline_trace"]],
                     str(cls.folder / "harness.cpp"), *objects, "-o", str(cls.binary)])

    @classmethod
    def compile(cls, command):
        result = subprocess.run(command, capture_output=True, text=True)
        if result.returncode:
            raise AssertionError(result.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def check(self, number):
        result = subprocess.run([str(self.binary), str(number)], capture_output=True, text=True, timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_actual_composition_descriptor_survives_close_and_native_envelope(self): self.check(0)
    def test_first_allocation_failure_has_no_leases_or_rights(self): self.check(1)
    def test_second_allocation_failure_releases_first_page_owner(self): self.check(2)
    def test_real_thread_close_cannot_free_while_create_allocates(self): self.check(3)
    def test_real_thread_close_after_observer_admission_never_publishes_open(self): self.check(4)
    def test_operation_admitted_before_close_cannot_return_descriptor_after_close(self): self.check(5)
    def test_rejected_adopt_stays_mig_owned_duplicate_does_not_release_owned_right(self): self.check(6)
    def test_close_after_take_blocks_commit_and_releases_delivery(self): self.check(7)
    def test_real_thread_publish_notify_lease_blocks_close_and_second_publisher(self): self.check(8)
    def test_copy_in_progress_keeps_closed_session_resources_for_retry(self): self.check(10)
    def test_identity_recheck_failure_precedes_clock_and_commit(self): self.check(11)
    def test_invalid_clock_microseconds_never_reach_ring(self): self.check(12)
    def test_failed_zero_argument_send_does_not_replay_committed_record(self): self.check(13)
    def test_actual_ring_full_requests_wake_without_overwrite(self): self.check(14)
    def test_close_before_create_is_terminal_without_allocating(self): self.check(15)
    def test_observer_admission_failure_cleans_allocation_and_owner(self): self.check(16)
    def test_foreign_task_cannot_adopt_or_retain_descriptor(self): self.check(17)
    def test_owned_action_frame_preserves_unknown_complete_tlv_in_native_ring(self): self.check(18)
    def test_captured_incomplete_action_frame_never_commits_or_notifies(self): self.check(19)
    def test_maximum_owned_action_frame_uses_resident_scratch_and_notifies_once(self): self.check(20)
    def test_queue_waits_for_real_subscription_instead_of_dropping_early_snapshot(self): self.check(21)
    def test_real_worker_drains_owned_event_to_real_ring_and_zero_argument_notification(self): self.check(22)
    def test_real_worker_notify_inflight_keeps_actual_session_resources_until_callback_finishes(self): self.check(23)
    def test_real_worker_notification_fault_closes_actual_session_without_replaying_commit(self): self.check(24)
    def test_real_router_halt_same_uc_reopen_new_mapping_and_action_frame_notification(self): self.check(25)
    def test_real_router_later_create_finishes_busy_halt_and_retries(self): self.check(26)
    def test_real_router_old_callback_cannot_consume_new_same_handle_event(self): self.check(27)
    def test_real_router_eight_resident_budget_never_closes_uc_control_registry(self): self.check(28)
    def test_real_router_lifecycle_collect_uses_closing_registry_lease(self): self.check(29)
    def test_actual_codec_message_counters_masks_and_empty_worker_callback(self): self.check(30)
    def test_router_last_observation_uses_newest_nonempty_resident_session(self): self.check(31)
    def test_publish_result_marks_only_taken_codec_attempts_with_actual_error(self): self.check(32)
    def test_source_20_40_80mhz_flags_preserve_complete_owned_body_in_native_ring(self): self.check(33)
    def test_invalid_channel_flag_combinations_never_commit_or_notify(self): self.check(34)
    def test_baseline_hook_observes_owned_source_without_changing_codec_publish(self): self.check(35)


if __name__ == "__main__":
    unittest.main()
