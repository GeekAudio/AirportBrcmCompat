// Default-unwired composition. This does not advertise selector5 or route APIs.
#ifndef AIRPORT_AWDL_EVENT_PIPE_SESSION_HPP
#define AIRPORT_AWDL_EVENT_PIPE_SESSION_HPP
#include "async_notification_owner.hpp"
#include "event_memory.hpp"
#include "event_pipe_core.hpp"
#include "event_pipe_worker.hpp"
#include "legacy_post_observer.hpp"
#include "../awdl_compat/awdl_message_codec.h"
#include "../awdl_compat/message48_subset_codec.h"
namespace AWDLKernel {
class EventPipeSession final {
public:
    struct PublishResult {
        IOReturn result=kIOReturnNotReady,notification=kIOReturnNotReady;
        uint32_t message=0,committed=0,dropped=0,full=0;
        // Set only after an owned snapshot was actually taken and its codec
        // invoked. Empty/admission/context returns leave these zero.
        uint32_t codecAttempted=0,codecError=0,codecRejectMask=0;
    };
    EventPipeSession()=default;
    EventPipeSession(const EventPipeSession &)=delete;
    EventPipeSession &operator=(const EventPipeSession &)=delete;
    // STATIC/RESIDENT OWNER ONLY. Storage must survive every entrant. No route
    // removal, implicit teardown, reuse after Closed, or readiness assertion.
    // The integration must keep future entry barriers until reboot.

    // Sleepable, outside captured WL/gate. Genuine current owner and actual
    // registry record; allocates first, authorizes/attaches on captured WL.
    // Observer must have been separately prepared and explicitly installed.
    // Backend and its live-image binding stay immutable/alive through close.
    // Even on failure close() may return Busy; keep this resident object alive.
    IOReturn create(ClientRegistry &,IOUserClient *,const DriverVersionBackend &,
                    const VersionCall &preparedVerification);
    // Genuine owner's IPC, outside the captured gate. Returns a retained MD;
    // IOKit owns that reference. Mapping itself remains IOKit's responsibility.
    IOReturn retainMemoryForType(uint32_t,IOOptionBits *,IOMemoryDescriptor **);
    // In captured gate, exact owner IPC. Successful adoption MUST be the final
    // successful RPC outcome; the caller may not return an error afterward.
    IOReturn subscribeFromSuccessfulDispatch(const IOExternalMethodArguments &);
    // Sleepable kernel consumer, outside gate. Rechecks pinned role6/awdl0 and
    // builds the actual native calendar-seconds/microseconds + padded BSD-name
    // envelope. Copies proven46/47 bodies and validates the strictly bounded
    // message48 receive subset. This does not implement message55.
    PublishResult drainOne();
    // Atomic admission stop is safe from early-close paths. Resource cleanup
    // requires close() outside the old gate and after our own operations drain.
    void beginClose();
    IOReturn close(); // non-waiting, Busy preserves resources
    EventPipeCore::Phase phase() const {return core_.phase();}
    uint32_t operations() const {return core_.operations();}
    EventPipeWorker::Snapshot workerSnapshot() const {return worker_.snapshot();}
private:
    class Operation;
    struct CreateCall;
    struct MemoryCall;
    struct PublishCall;
    static IOReturn createAction(OSObject *,void *,void *,void *,void *);
    static IOReturn bindWorkerAction(OSObject *,void *,void *,void *,void *);
    static IOReturn memoryAction(OSObject *,void *,void *,void *,void *);
    static IOReturn publishAction(OSObject *,void *,void *,void *,void *);
    bool activeInGate() const;
    AsyncNotificationOwner::Context context() const;
    EventPipeCore core_;
    ClientRegistry *registry_=nullptr;
    const DriverVersionBackend *backend_=nullptr;
    ClientWorkLease owner_;
    EventMemory memory_;
    AsyncNotificationOwner notification_;
    EventPipeWorker worker_;
    ObserverHandle observer_ {};
    bool observerBound_=false,subscribed_=false,publishing_=false;
    // Only the exclusive Publisher touches these resident scratch buffers.
    // Keeping the receive snapshot and codec output off the kernel stack also
    // keeps them distinct for the codec's no-alias contract.
    OwnedPostEvent source_ {};
    awcm48_event actionFrame_ {};
};
}
#endif
