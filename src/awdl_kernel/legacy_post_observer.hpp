// Resident, default-off producer observer. Not in any production builder.
#ifndef AIRPORT_AWDL_LEGACY_POST_OBSERVER_HPP
#define AIRPORT_AWDL_LEGACY_POST_OBSERVER_HPP
#include "client_registry.hpp"
#include "legacy_post_observer_core.hpp"
#include <Headers/kern_patcher.hpp>

namespace AWDLKernel { namespace LegacyPostObserver {
enum class Status : uint32_t {
    Passed=0,NotPrepared,NotInstalled,Argument,Context,RegistryRejected,
    BackendRejected,Capacity,Duplicate,Closing,Stale,Empty,Busy,Pins,Route,Retiring
};
struct AdmissionResult {
    Status status=Status::Argument;
    ClientStatus registryStatus=ClientStatus::Argument;
    VersionResult verification {};
};
struct Counters {
    uint32_t installed=0,admitted=0,captured=0,droppedShape=0,droppedState=0,
        droppedFull=0,droppedRegistry=0,delivered=0,closed=0;
};
// Install-only numeric observations, not readiness or readable-VM authority.
// UINT32_MAX means not reached. Fields are independent atomic samples if a
// diagnostic query overlaps installation; no addresses or event bytes escape.
struct InstallSnapshot {
    // 0 not called, 1 context, 2 image pins, 3 symbols, 4 calls, 5 route, 6 done.
    uint32_t phase=0,pinStatus=UINT32_MAX;
    // Context: IRQ1, interrupts-enabled2, lock-present4, prior-attempt8.
    // Symbols: Post exact1, AF exact2, allocator resolved4, memcpy resolved8.
    uint32_t context=0,symbolMask=0;
    // Calls: bit0 allocate, bit1 metadata memcpy, bit2 frame memcpy.
    uint32_t callShapeMask=0,callTargetMask=0;
    // 0 route+original succeeded, 1 route returned false, 2 original NULL.
    uint32_t routeResult=UINT32_MAX,patcherError=0;
};
class DeliveryLease final {
    friend Status take(const ObserverHandle &,OwnedPostEvent &,DeliveryLease &);
    ObserverDelivery token {};
public:
    DeliveryLease()=default;
    ~DeliveryLease();
    DeliveryLease(const DeliveryLease &)=delete;
    DeliveryLease &operator=(const DeliveryLease &)=delete;
    Status release();
};
// Static owner/lock/route and bounded registration tombstones live until reboot.
// No unload/free/reset API: capture drain is not physical-producer quiescence.
// Sleepable initialization, OUTSIDE the old controller gate; allocates one lock.
Status prepare();
// Explicit opt-in only; caller owns readable mapped image until reboot and has
// verified the actual running kernel/namespace dependencies. Exact Legacy UUID,
// __text and all complete PIC/call-site guards precede the one post-entry route.
// No callers/production builder currently invoke this function.
Status install(KernelPatcher &,size_t legacyIndex,mach_vm_address_t,size_t);
// Genuine current owner task, already on the captured enabled controller gate.
// preparedVerification buffers are allocated/initialized OUTSIDE that gate.
// Acquires a real registry WorkLease, verifies its generation and actual GET43
// task/entitlement/provider/role6/awdl0 identity, then publishes this session.
// No bool authorization or arbitrary function pointer can be supplied.
// Strict same-connection reopen: only an existing logical Closing record with
// same real registry generation, own drain0 and a previously bound OLD typed
// worker.canReplaceBinding() (Stopped + immutable OLD Session Closed). Rechecks
// actual owner/topology/GET43. Provider/controller retirement and RegistryClosing
// remain terminal. Keeps registration lease/queue serial; next cycle must bind
// its NEW resident worker. Active/Pending/unbound/unknown old states refuse.
AdmissionResult subscribe(ClientRegistry &,IOUserClient *,const DriverVersionBackend &,
                           const VersionCall &preparedVerification,ObserverHandle &);
// Actual current owner task on the captured enabled controller WL gate. The
// worker has already been privately prepared by its owning EventPipeSession;
// its immutable binding must match this actual subscribe-produced handle.
// Worker/Session storage stays resident until reboot. No arbitrary callback.
// Binding does not declare readiness/schedule old queued data: after Session
// Ready is published, its owner must kick once OUTSIDE the old gate.
Status bindWorker(const ObserverHandle &,EventPipeWorker &);
// Original lifecycle/authorized session owner calls these BEFORE underlying
// registry/provider close. Bounded marking/cancel only, no wait/IOKit calls.
// Repeated calls preserve the handle. They do not invoke the foreign old reset.
Status beginClose(IOUserClient *,ObserverHandle &);
Status beginCloseProvider(IOService *,ObserverHandle &);
size_t beginCloseController(IOService *);
void retire(); // irreversible admission barrier + closes all current sessions
// Counts only our copy reservations/queued snapshots/delivery leases. It does
// not release the retained registration or claim producer/port/map/ACK drain.
Status pollDrain(const ObserverHandle &,ObserverDrain &);
// Bounded owned copy (up to2048 body bytes); no provider call/gate wait. The returned bytes contain
// protocol identities: consume internally, never log/export them. Keep the
// delivery lease until the downstream owned work has completed or been dropped.
// 48 is ONLY a strict source/length envelope here; the consumer MUST run actual
// awcm48_translate before ring publication. No 2KB codec output on the IRQ tap.
Status take(const ObserverHandle &,OwnedPostEvent &,DeliveryLease &);
Counters counters();
InstallSnapshot installSnapshot();
} } // namespace AWDLKernel::LegacyPostObserver
#endif
