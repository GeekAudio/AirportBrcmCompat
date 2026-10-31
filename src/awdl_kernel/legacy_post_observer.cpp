#include "legacy_post_observer.hpp"
#include "legacy_post_observer_pins.hpp"
#include "event_pipe_worker.hpp"
#include <IOKit/network/IONetworkController.h>
#include <IOKit/IOLib.h>
#include <kern/task.h>
#include <machine/machine_routines.h>

namespace AWDLKernel { namespace LegacyPostObserver { namespace {
using Post=IOReturn (*)(IOService *,uint32_t,void *,size_t);
using GetRole=uint32_t (*)(IOService *);
using GetBSDName=const char *(*)(IOService *);
constexpr const char *AFName="__ZN22IO80211AWDLPeerManager12postAFToP2pdEPKvmP22apple80211_act_frm_hdr";
constexpr const char *PostName="__ZN23IO80211VirtualInterface27IO80211InterfacePostMessageEjPvm";
struct Session {
    ClientRegistry *registry=nullptr;
    ObserverHandle handle {};
    ClientWorkLease lifetime; // Retained registration; never auto-finished/free.
};
IOSimpleLock *lock=nullptr;
LegacyPostObserverCore core;
Session sessions[ObserverSessions];
ObserverPins pins;
uintptr_t allocationTarget=0,copyTarget=0;
Post originalPost=nullptr;
volatile uint32_t installed=0;
bool attempted=false; // Install is serialized by the live-image owner.
Counters statistics {};
InstallSnapshot installation {};
void installField(uint32_t &field,uint32_t value) {
    __atomic_store_n(&field,value,__ATOMIC_RELAXED);
}
void installPhase(uint32_t phase) {__atomic_store_n(&installation.phase,phase,__ATOMIC_RELEASE);}
void installError(KernelPatcher &patcher) {
    installField(installation.patcherError,static_cast<uint32_t>(patcher.getError()));
}
void increment(uint32_t &n) {__atomic_add_fetch(&n,1U,__ATOMIC_RELAXED);}
bool same(const ObserverHandle &a,const ObserverHandle &b) {
    return a.client==b.client && a.generation==b.generation;
}
Status status(ObserverCoreStatus s) {
    switch (s) {
        case ObserverCoreStatus::Passed:return Status::Passed;
        case ObserverCoreStatus::Capacity:case ObserverCoreStatus::Full:case ObserverCoreStatus::Overflow:return Status::Capacity;
        case ObserverCoreStatus::Duplicate:return Status::Duplicate;
        case ObserverCoreStatus::Closing:case ObserverCoreStatus::Pending:return Status::Closing;
        case ObserverCoreStatus::Stale:case ObserverCoreStatus::Missing:return Status::Stale;
        case ObserverCoreStatus::Empty:return Status::Empty;
        case ObserverCoreStatus::Busy:return Status::Busy;
        case ObserverCoreStatus::Retiring:return Status::Retiring;
        default:return Status::Argument;
    }
}
IOSimpleLock *getLock() {return __atomic_load_n(&lock,__ATOMIC_ACQUIRE);}
bool sleepable() {return !ml_at_interrupt_context() && ml_get_interrupts_enabled();}
bool admissionContext(const ClientWorkLease &lease) {
    auto *loop=lease.workLoop();auto *gate=lease.gate();
    return lease.client() && lease.owner()==current_task() && lease.controller() &&
        lease.provider() && lease.provider()->getMetaClass() &&
        lease.provider()->getMetaClass()->getClassSize()>=0xde &&
        loop && gate && loop->inGate() &&
        gate->getWorkLoop()==loop && gate->isEnabled();
}
bool sourcePinsLive() {
    if (revalidateObserverSources(pins)!=ObserverPinStatus::Passed || !allocationTarget || !copyTarget) return false;
    uintptr_t allocate=0,header=0,frame=0;
    const auto *image=reinterpret_cast<const void *>(pins.base);
    return observerRelativeCallTarget(image,pins.extent,0x3f1aa,allocate) &&
        observerRelativeCallTarget(image,pins.extent,0x3f1d4,header) &&
        observerRelativeCallTarget(image,pins.extent,0x3f1f1,frame) &&
        allocate==allocationTarget && header==copyTarget && frame==copyTarget;
}
bool leafIdentity(IOService *provider) {
    const char *bsd=reinterpret_cast<GetBSDName>(pins.bsdName)(provider);
    return reinterpret_cast<GetRole>(pins.role)(provider)==6 &&
        bsd==reinterpret_cast<const char *>(provider)+0xd8 && !memcmp(bsd,"awdl0",6);
}
bool bindingTopology(const ClientWorkLease &work) {
    if (!admissionContext(work)) return false;
    auto *controller=OSDynamicCast(IONetworkController,work.controller());
    auto *provider=work.provider();auto *loop=work.workLoop();
    return controller && controller->getCommandGate()==work.gate() &&
        !controller->isInactive() && !provider->isInactive() && !work.client()->isInactive() &&
        controller->getWorkLoop()==loop && provider->getWorkLoop()==loop &&
        provider->getProvider()==controller && work.client()->getProvider()==provider &&
        work.client()->getWorkLoop()==loop && leafIdentity(provider);
}
void cancelAdmission(size_t index,const ObserverHandle &h,bool reopening=false) {
    auto *guard=getLock();
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(guard);
    if (reopening) {
        core.cancelReopen(h);IOSimpleLockUnlockEnableInterrupt(guard,irq);return;
    }
    const auto canceled=core.cancelPending(h);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (canceled!=ObserverCoreStatus::Passed) return; // Keep refs on invariant failure.
    if (sessions[index].lifetime.client()) sessions[index].lifetime.release();
    irq=IOSimpleLockLockDisableInterrupt(guard);
    sessions[index].registry=nullptr;sessions[index].handle={};
    core.eraseCanceled(h);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
}
// Unknown original producer thread, possibly interrupt context. Do NOT add
// IOKit virtual calls, task checks, allocation, gate acquisition or notification.
void capture(IOService *provider,uintptr_t returnPC,uint32_t message,void *data,size_t length) {
    if (!__atomic_load_n(&installed,__ATOMIC_ACQUIRE)) return;
    auto *guard=getLock();if (!guard) return;
    if (returnPC<pins.base || returnPC-pins.base>=pins.extent ||
        !observerPostShape(returnPC-pins.base,message,data,length)) {
        increment(statistics.droppedShape);return;
    }
    ObserverCapture token;ObserverBinding binding;
    ClientRegistry *registry=nullptr;uint8_t *owned=nullptr;
    IOInterruptState irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto reserved=core.begin(reinterpret_cast<uintptr_t>(provider),returnPC-pins.base,
                                  message,data,length,token,binding);
    if (reserved==ObserverCoreStatus::Passed) {
        owned=core.buffer(token);
        for (auto &session:sessions) if (same(session.handle,token.owner)) {registry=session.registry;break;}
    }
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (reserved!=ObserverCoreStatus::Passed) {
        if (reserved==ObserverCoreStatus::Full) increment(statistics.droppedFull);
        else increment(statistics.droppedState);
        return;
    }
    // The stored real client is held by the permanent admission lease. Acquire
    // the SAME registry generation atomically; no lookup-then-acquire race and
    // no current-task requirement on genuine kernel producer callbacks.
    ClientWorkLease work;
    const bool authorized=registry && owned &&
        registry->acquire(reinterpret_cast<IOUserClient *>(binding.client),work)==ClientStatus::Passed &&
        work.generation()==binding.generation &&
        reinterpret_cast<uintptr_t>(work.provider())==binding.provider &&
        reinterpret_cast<uintptr_t>(work.controller())==binding.controller;
    // Fixed complete leaf bodies only: role loads provider+c0, BSDName returns
    // provider+d8. They acquire no gate and call no IOKit virtual method. The
    // real admission checked exact class/size; the current WorkLease holds it.
    const bool identity=authorized && leafIdentity(work.provider());
    if (!identity) {
        irq=IOSimpleLockLockDisableInterrupt(guard);core.abort(token);
        IOSimpleLockUnlockEnableInterrupt(guard,irq);
        if (work.client()) work.release();increment(statistics.droppedRegistry);return;
    }
    // Exact46 is NULL/0; exact47 is a wired producer-stack local. Exact48
    // is the final IOMallocZero(72+frameLen) flat buffer in postAFToP2pd;
    // its destructor runs only AFTER this synchronous call returns. All copies
    // happen before original. No generic/tail source or borrowed pointer exits.
    // 48 frame/header/TLV validation belongs to the real downstream codec.
    if (length) memcpy(owned,data,length);
    irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto committed=core.commit(token);
    EventPipeWorker *worker=committed==ObserverCoreStatus::Passed?core.worker(token.owner):nullptr;
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    work.release(); // MUST precede original BSD/old-UC dispatch below.
    if (committed==ObserverCoreStatus::Passed) {
        increment(statistics.captured);
        // Typed resident object only; no observer lock or capture WorkLease is
        // held. A late close clears future borrows and the worker rejects this
        // already-borrowed handle once Closing. No source pointer is passed.
        if (worker) (void)worker->kickFromProducer(token.owner);
    }
    else if (committed==ObserverCoreStatus::Shape) increment(statistics.droppedShape);
    else increment(statistics.droppedState);
}
__attribute__((noinline)) IOReturn wrappedPost(IOService *provider,uint32_t message,void *data,size_t length) {
    const auto returnPC=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    // Lilu publishes this trampoline before patching the original entry. A
    // partially installed route remains pure pass-through while installed==0.
    return observerForward(capture,originalPost,provider,returnPC,message,data,length);
}
} // namespace

Status prepare() {
    if (getLock()) return Status::Passed;
    if (!sleepable()) return Status::Context;
    auto *fresh=IOSimpleLockAlloc();if (!fresh) return Status::Capacity;
    IOSimpleLock *expected=nullptr;
    if (!__atomic_compare_exchange_n(&lock,&expected,fresh,false,__ATOMIC_RELEASE,__ATOMIC_ACQUIRE))
        IOSimpleLockFree(fresh); // Only the unpublished lock may be freed.
    return Status::Passed;
}
Status install(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size) {
    installField(installation.pinStatus,UINT32_MAX);
    installField(installation.symbolMask,0);installField(installation.callShapeMask,0);
    installField(installation.callTargetMask,0);installField(installation.routeResult,UINT32_MAX);
    installError(patcher);
    // Observe only; retain the original independent context/guard decisions.
    // bit0 IRQ, bit1 interrupts enabled, bit2 lock, bit3 prior route attempt.
    installField(installation.context,(ml_at_interrupt_context()?1U:0U)|
        (ml_get_interrupts_enabled()?2U:0U)|(getLock()?4U:0U)|(attempted?8U:0U));
    installPhase(1);
    if (!getLock()) return Status::NotPrepared;
    if (!sleepable()) return Status::Context;
    if (attempted) return Status::Duplicate;
    installPhase(2);
    ObserverPins verified;
    const auto pinStatus=initializeObserverPins(reinterpret_cast<const void *>(address),size,verified);
    installField(installation.pinStatus,static_cast<uint32_t>(pinStatus));
    if (pinStatus!=ObserverPinStatus::Passed)
        return Status::Pins;
    // No production caller installs this independent module. Guards include
    // full PIC20 at entry and complete stable producer/call-site instructions.
    installPhase(3);
    const auto post=patcher.solveSymbol(index,PostName,address,size);
    installError(patcher);
    const auto af=patcher.solveSymbol(index,AFName,address,size);
    installError(patcher);
    const uint32_t symbols=(post==verified.entry?1U:0U)|(af==verified.base+0x3f170?2U:0U);
    installField(installation.symbolMask,symbols);
    if (symbols!=3U) return Status::Pins;
    // Three loader-relocated E8 operands are NOT compared to archive zeros.
    // Verify their actual destinations against the real running kernel symbols.
    const auto allocate=patcher.solveSymbol(KernelPatcher::KernelID,"_IOMallocZero");
    installError(patcher);
    const auto copy=patcher.solveSymbol(KernelPatcher::KernelID,"___memcpy_chk");
    installError(patcher);
    installField(installation.symbolMask,symbols|(allocate?4U:0U)|(copy?8U:0U));
    installPhase(4);
    uintptr_t allocated=0,copiedHeader=0,copiedFrame=0;
    const auto *image=reinterpret_cast<const void *>(address);
    const bool allocationShape=observerRelativeCallTarget(image,size,0x3f1aa,allocated);
    const bool headerShape=observerRelativeCallTarget(image,size,0x3f1d4,copiedHeader);
    const bool frameShape=observerRelativeCallTarget(image,size,0x3f1f1,copiedFrame);
    installField(installation.callShapeMask,(allocationShape?1U:0U)|(headerShape?2U:0U)|(frameShape?4U:0U));
    installField(installation.callTargetMask,
        (allocationShape && allocate && allocated==allocate?1U:0U)|
        (headerShape && copy && copiedHeader==copy?2U:0U)|
        (frameShape && copy && copiedFrame==copy?4U:0U));
    if (!allocate || !copy || !allocationShape || !headerShape || !frameShape ||
        allocated!=allocate || copiedHeader!=copy || copiedFrame!=copy) return Status::Pins;
    attempted=true;pins=verified;allocationTarget=allocate;copyTarget=copy;
    KernelPatcher::RouteRequest request(PostName,wrappedPost,originalPost);
    installPhase(5);
    const bool routed=patcher.routeMultiple(index,&request,1,address,size);
    installError(patcher);
    installField(installation.routeResult,!routed?1U:!originalPost?2U:0U);
    if (!routed || !originalPost) return Status::Route;
    __atomic_store_n(&installed,1U,__ATOMIC_RELEASE);installPhase(6);return Status::Passed;
}
AdmissionResult subscribe(ClientRegistry &registry,IOUserClient *client,
    const DriverVersionBackend &backend,const VersionCall &verification,ObserverHandle &out) {
    out={};AdmissionResult result;
    if (!getLock()) {result.status=Status::NotPrepared;return result;}
    if (!__atomic_load_n(&installed,__ATOMIC_ACQUIRE)) {result.status=Status::NotInstalled;return result;}
    if (!client || !sleepable()) {result.status=Status::Context;return result;}
    if (!sourcePinsLive()) {result.status=Status::Pins;return result;}
    ClientWorkLease initial;
    result.registryStatus=registry.acquire(client,initial);
    if (result.registryStatus!=ClientStatus::Passed) {result.status=Status::RegistryRejected;return result;}
    if (!bindingTopology(initial)) {result.status=Status::Context;return result;}
    ObserverBinding binding {reinterpret_cast<uintptr_t>(client),reinterpret_cast<uintptr_t>(initial.provider()),
        reinterpret_cast<uintptr_t>(initial.controller()),initial.generation()};
    size_t index=ObserverSessions;ObserverHandle h;bool reopening=false;EventPipeWorker *oldWorker=nullptr;
    auto *guard=getLock();IOInterruptState irq=IOSimpleLockLockDisableInterrupt(guard);
    auto reserved=core.reserve(binding,index,h);
    if (reserved==ObserverCoreStatus::Duplicate) {
        reserved=core.reserveReopen(binding,index,h,oldWorker);
        reopening=reserved==ObserverCoreStatus::Passed;
    } else if (reserved==ObserverCoreStatus::Passed) {
        sessions[index].handle=h;sessions[index].registry=&registry;
    }
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (reserved!=ObserverCoreStatus::Passed) {result.status=status(reserved);return result;}
    if (reopening) {
        // The long registration lease is kept, not replaced/released. Old
        // worker and its immutable Session are resident; no old pointer can
        // start consuming this new cycle. No caller bool supplies this proof.
        if (sessions[index].registry!=&registry || !same(sessions[index].handle,h) ||
            sessions[index].lifetime.client()!=client ||
            sessions[index].lifetime.generation()!=h.generation || !oldWorker ||
            !oldWorker->canReplaceBinding()) {
            cancelAdmission(index,h,true);result.status=Status::Closing;return result;
        }
    } else {
        result.registryStatus=registry.acquire(client,sessions[index].lifetime);
        if (result.registryStatus!=ClientStatus::Passed || sessions[index].lifetime.generation()!=h.generation) {
            cancelAdmission(index,h);result.status=Status::RegistryRejected;return result;
        }
    }
    // This is actual authorization, not a caller assertion or fixture boolean.
    // Buffers are kernel-owned and prepared outside the old gate by the owner.
    result.verification=backend.get43(initial.owner(),initial.controller(),initial.provider(),verification);
    if (result.verification.status!=VersionStatus::Passed || !bindingTopology(initial) || !sourcePinsLive()) {
        cancelAdmission(index,h,reopening);result.status=Status::BackendRejected;return result;
    }
    ClientWorkLease current;
    result.registryStatus=registry.acquire(client,current);
    if (result.registryStatus!=ClientStatus::Passed || current.generation()!=h.generation) {
        cancelAdmission(index,h,reopening);result.status=Status::RegistryRejected;return result;
    }
    if (reopening && !oldWorker->canReplaceBinding()) {
        cancelAdmission(index,h,true);result.status=Status::Closing;return result;
    }
    irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto activated=reopening?core.activateReopen(h,oldWorker):core.activate(h);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (activated!=ObserverCoreStatus::Passed) {cancelAdmission(index,h,reopening);result.status=status(activated);return result;}
    out=h;result.status=Status::Passed;increment(statistics.admitted);return result;
}
Status bindWorker(const ObserverHandle &h,EventPipeWorker &worker) {
    auto *guard=getLock();if (!guard) return Status::NotPrepared;
    if (!__atomic_load_n(&installed,__ATOMIC_ACQUIRE)) return Status::NotInstalled;
    if (!sleepable()) return Status::Context;
    if (!sourcePinsLive()) return Status::Pins;
    ObserverBinding binding;ClientRegistry *registry=nullptr;
    auto irq=IOSimpleLockLockDisableInterrupt(guard);
    auto checked=core.activeBinding(h,binding);
    if (checked==ObserverCoreStatus::Passed)
        for (auto &session:sessions) if (same(session.handle,h)) {registry=session.registry;break;}
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (checked!=ObserverCoreStatus::Passed) return status(checked);
    ClientWorkLease work;
    if (!registry || registry->acquire(reinterpret_cast<IOUserClient *>(h.client),work)!=ClientStatus::Passed ||
        work.generation()!=h.generation || reinterpret_cast<uintptr_t>(work.provider())!=binding.provider ||
        reinterpret_cast<uintptr_t>(work.controller())!=binding.controller) return Status::RegistryRejected;
    // These real IOKit checks run ONLY here, with genuine retained references,
    // current owner task, and the captured old controller gate already held.
    if (!bindingTopology(work)) return Status::Context;
    if (!worker.matchesBinding(h)) return Status::Stale;
    irq=IOSimpleLockLockDisableInterrupt(guard);
    // Actual lifecycle closes this observer before closing its worker. If a
    // separate worker fault races this point, the resident late kick still
    // rejects safely; binding success itself is never a global-ready proof.
    checked=core.bindWorker(h,&worker);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    return status(checked);
}
Status beginClose(IOUserClient *client,ObserverHandle &out) {
    out={};auto *guard=getLock();if (!guard) return Status::NotPrepared;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto s=core.beginCloseClient(reinterpret_cast<uintptr_t>(client),out);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (s==ObserverCoreStatus::Passed) increment(statistics.closed);return status(s);
}
Status beginCloseProvider(IOService *provider,ObserverHandle &out) {
    out={};auto *guard=getLock();if (!guard) return Status::NotPrepared;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto s=core.beginCloseProvider(reinterpret_cast<uintptr_t>(provider),out);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    if (s==ObserverCoreStatus::Passed) increment(statistics.closed);return status(s);
}
size_t beginCloseController(IOService *controller) {
    auto *guard=getLock();if (!guard) return 0;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);
    const auto count=core.beginCloseController(reinterpret_cast<uintptr_t>(controller));
    IOSimpleLockUnlockEnableInterrupt(guard,irq);return count;
}
void retire() {
    auto *guard=getLock();if (!guard) return;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);core.retire();
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
}
Status pollDrain(const ObserverHandle &h,ObserverDrain &out) {
    out={};auto *guard=getLock();if (!guard) return Status::NotPrepared;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);const auto s=core.drain(h,out);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);return status(s);
}
Status take(const ObserverHandle &h,OwnedPostEvent &out,DeliveryLease &lease) {
    memset(&out,0,sizeof(out));if (lease.token.sequence) return Status::Busy;
    auto *guard=getLock();if (!guard) return Status::NotPrepared;
    const OwnedPostEvent *owned=nullptr;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);const auto s=core.reserveTake(h,owned,lease.token);
    IOSimpleLockUnlockEnableInterrupt(guard,irq);
    // Its Delivering reservation prevents close/reuse/clear until lease release.
    // Copy up to2048 bytes outside the simple lock; caller storage is preowned.
    if (s==ObserverCoreStatus::Passed) {out=*owned;increment(statistics.delivered);}
    return status(s);
}
DeliveryLease::~DeliveryLease() {if (token.sequence) release();}
Status DeliveryLease::release() {
    auto *guard=getLock();if (!guard || !token.sequence) return Status::Argument;
    const auto irq=IOSimpleLockLockDisableInterrupt(guard);const auto s=core.finish(token);
    if (s==ObserverCoreStatus::Passed) token={};
    IOSimpleLockUnlockEnableInterrupt(guard,irq);return status(s);
}
Counters counters() {
    Counters out;
#define LOAD(field) out.field=__atomic_load_n(&statistics.field,__ATOMIC_RELAXED)
    LOAD(admitted);LOAD(captured);LOAD(droppedShape);LOAD(droppedState);
    LOAD(droppedFull);LOAD(droppedRegistry);LOAD(delivered);LOAD(closed);
#undef LOAD
    out.installed=__atomic_load_n(&installed,__ATOMIC_ACQUIRE);return out;
}
InstallSnapshot installSnapshot() {
    InstallSnapshot out;
    out.phase=__atomic_load_n(&installation.phase,__ATOMIC_ACQUIRE);
#define LOAD_INSTALL(field) out.field=__atomic_load_n(&installation.field,__ATOMIC_RELAXED)
    LOAD_INSTALL(pinStatus);LOAD_INSTALL(context);LOAD_INSTALL(symbolMask);
    LOAD_INSTALL(callShapeMask);LOAD_INSTALL(callTargetMask);LOAD_INSTALL(routeResult);LOAD_INSTALL(patcherError);
#undef LOAD_INSTALL
    return out;
}
} } // namespace AWDLKernel::LegacyPostObserver
