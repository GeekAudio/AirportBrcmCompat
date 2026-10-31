// Unwired registry only: no IOUserClient construction, slot, hook or ready flag.
#ifndef AIRPORT_AWDL_CLIENT_REGISTRY_HPP
#define AIRPORT_AWDL_CLIENT_REGISTRY_HPP
#include "client_registry_core.hpp"
#include "driver_version_backend.hpp"
#include <IOKit/IOUserClient.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>

namespace AWDLKernel {
class ClientRegistry;
class ClientWorkLease final {
    friend class ClientRegistry;
    ClientRegistry *registry=nullptr;
    ClientSnapshot snapshot {};
public:
    ClientWorkLease()=default;
    ~ClientWorkLease();
    ClientWorkLease(const ClientWorkLease &)=delete;
    ClientWorkLease &operator=(const ClientWorkLease &)=delete;
    ClientStatus release();
    uint64_t generation() const {return snapshot.handle.generation;}
    IOUserClient *client() const {return reinterpret_cast<IOUserClient *>(snapshot.objects.client);}
    task_t owner() const {return reinterpret_cast<task_t>(snapshot.objects.task);}
    IOService *controller() const {return reinterpret_cast<IOService *>(snapshot.objects.controller);}
    IOService *provider() const {return reinterpret_cast<IOService *>(snapshot.objects.provider);}
    IOCommandGate *gate() const {return reinterpret_cast<IOCommandGate *>(snapshot.objects.gate);}
    IOWorkLoop *workLoop() const {return reinterpret_cast<IOWorkLoop *>(snapshot.objects.loop);}
    // These references prove object lifetime only. They do not grant a gate,
    // entitlement, firmware permission or provider teardown exclusion lease.
};
using WorkLease=ClientWorkLease;
using CloseHandle=ClientHandle; // Token only; acquire a WorkLease before borrowing objects.
struct ClientRegistrationResult {
    ClientStatus status=ClientStatus::Argument;
    VersionResult verification {};
};
class ClientRegistry final {
    friend class ClientWorkLease;
    IOSimpleLock *lock=nullptr;
    ClientRegistryCore core {};
    ClientStatus release(ClientWorkLease &);
    ClientRegistrationResult registerValidated(IOUserClient *,task_t,IOService *,IOService *,
        const DriverVersionBackend &,const VersionCall &,ClientHandle &,bool pending);
public:
    ClientRegistry()=default;
    ClientRegistry(const ClientRegistry &)=delete;
    ClientRegistry &operator=(const ClientRegistry &)=delete;
    // STATIC OWNER LIFETIME ONLY. No destructor or free-lock API is supplied.
    // The owner must keep this storage/lock alive across all hook entries,
    // including callers not yet at the lock. Unload/reclamation requires real
    // route removal and an entry barrier not implemented by this component.
    // Never create this registry on a temporary stack or delete its owner.
    ClientStatus prepare();

    // Sleepable current-owner task context, on the genuine controller gate.
    // Caller already owns/retains client/task/controller/provider and excludes
    // teardown. The actual AsyncUC was initialized with this task by the real
    // audited constructor path; no task field offset is guessed here.
    // Prepare+initialize both verification buffers OUTSIDE the old gate. This
    // function allocates none; it calls the actual GET43 backend, whose real
    // task entitlements/role/name/gate checks decide admission, never a bool.
    // Registration references are acquired/released outside the simple lock.
    ClientRegistrationResult registerClient(IOUserClient *,task_t owner,
        IOService *controller,IOService *provider,const DriverVersionBackend &,
        const VersionCall &preparedVerification,ClientHandle &);
    // Pre-allocation capacity/provider check only, not a reservation or auth.
    ClientStatus admission(IOService *provider);
    // Actual constructor immediately precedes this call on the same original
    // controller gate. Strict old class/size0x158/type2/task/no provider/private
    // pointers are validated along with the genuine GET43 authorization. Hold
    // refs BEFORE start/attach; Pending rejects external work but lifecycle
    // hooks can acquireClosing to safely scope a failed original start.
    ClientRegistrationResult reserveClient(IOUserClient *,task_t owner,
        IOService *controller,IOService *provider,const DriverVersionBackend &,
        const VersionCall &preparedVerification,ClientHandle &);
    // Called only after original start succeeded, on captured gate. Validates
    // actual attachment/private provider/owner then atomically rejects Closing.
    ClientStatus activateClient(const ClientHandle &);

    // Unknown original-hook thread: compares the genuine live client key only,
    // no dereference/IOKit/task/gate work under lock. A delayed raw pointer is
    // not a valid original-hook lifetime. Current generation is acquired in the
    // SAME critical section, not by a separate lookup. No deferred raw aliases.
    ClientStatus acquire(IOUserClient *client,ClientWorkLease &);
    // Only a genuine original reset/stop/close lifecycle hook may use this.
    // It permits an already Closing record but rejects removal-in-progress.
    // No current-task check: kernel stop can run for a previously authorized
    // owner. This is not external control or an entitlement bypass.
    ClientStatus acquireClosing(IOUserClient *client,ClientWorkLease &);
    // Any hook thread may atomically reject new work. Repeating during closing
    // returns the same handle. No waiting, gate, callback or reference release.
    ClientStatus beginClose(IOUserClient *client,ClientHandle &closeHandle);
    // Original provider/controller lifecycle hook only. Bounded atomic marking,
    // no object dereference or waiting. Does not tombstone a future creation:
    // the integration's own admission barrier must also close before teardown.
    ClientStatus beginCloseProvider(IOService *provider,ClientHandle &closeHandle);
    size_t beginCloseController(IOService *controller);
    // OUTSIDE the old controller gate, sleepable with interrupts enabled. Never
    // wait for inflight work: Busy leaves the closing entry retained for retry.
    // A short finishing reservation protects WorkLoop during its out-of-lock
    // context check. Final object/task releases occur outside the simple lock.
    // This proves REGISTRY drain only. It does not unregister/drain producers,
    // async rights/maps or authorize original reset/stop on a foreign client.
    ClientStatus finishClose(const ClientHandle &closeHandle);
};
} // namespace AWDLKernel
#endif
