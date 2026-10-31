#ifndef AIRPORT_AWDL_ASYNC_NOTIFICATION_OWNER_HPP
#define AIRPORT_AWDL_ASYNC_NOTIFICATION_OWNER_HPP

#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>

namespace AWDLKernel {

// Notification-right ownership only. No IOUC construction, selector5 policy,
// event source, ring, map, entitlement check or provider teardown lease.
class AsyncNotificationOwner final {
public:
    struct Context {
        IOUserClient *client;
        IOWorkLoop *loop;
        uint64_t generation;
    };
    enum class State : uint32_t { Empty, Subscribed, Closing, Retiring, Closed };
    struct Snapshot {
        State state {State::Empty};
        uint32_t inFlight {0};
        uint64_t adopted {0}, notifyAttempts {0}, notifySucceeded {0};
        uint64_t notifyFailed {0}, releaseAttempts {0};
        IOReturn lastSend {kIOReturnNotReady};
        IOReturn lastRelease {kIOReturnSuccess};
    };

    AsyncNotificationOwner() = default;
    AsyncNotificationOwner(const AsyncNotificationOwner &) = delete;
    AsyncNotificationOwner &operator=(const AsyncNotificationOwner &) = delete;

    // STORAGE LIFETIME: keep this object alive until close() succeeds and all
    // callers that could enter its methods have been excluded. No implicit
    // destructor cleanup is attempted from an unknown gate/thread context.
    // Closed is terminal: this component has one subscription, no replacement.
    // Reusing storage requires a separate real entry barrier, not a generation
    // integer or an IOUC retain alone.

    // All contexts come from genuine retained caller/registry leases. The same
    // real provider WorkLoop serializes every state operation. Those leases
    // cover the ENTIRE call, including time outside its gate. Retains below
    // protect C++ objects only; the caller still excludes provider teardown.
    // No arbitrary bool or this Context by itself proves authorization.

    // In the genuine captured WorkLoop gate; valid MIG selector2 arguments.
    // Success ADOPTS the RPC's MAKE_SEND right, without adding another right.
    // The enclosing RPC MUST finally return kIOReturnSuccess. On any error,
    // ownership remains with MIG request cleanup: do not release it here.
    IOReturn adoptFromSuccessfulDispatch(const Context &,
                                         const IOExternalMethodArguments &);

    // Sleepable and OUTSIDE the captured gate; no simple/spin lock held.
    // Short WorkLoop actions admit/complete our own notification lease. The
    // real zero-argument send and final temporary reference releases occur
    // outside that gate. A second concurrent notification returns Busy.
    // Caller has already committed a real ring record. A successful send is
    // not a daemon acknowledgement and this function does not replay events.
    IOReturn notifyZeroArgs(const Context &);

    // In the captured gate. Stop new notification admission; never wait.
    IOReturn beginClose(const Context &);
    // Sleepable, outside captured gate. Mark closing; if own notification is
    // in flight return Busy with resources retained. Otherwise move out and
    // release the right and C++ owner references OUTSIDE the gate. Idempotent.
    IOReturn close(const Context &);

    // Numeric data only, in the captured gate. Not a readiness predicate.
    IOReturn snapshotInGate(const Context &, Snapshot &) const;

private:
    struct NotifyCall;
    struct CloseCall;
    static IOReturn beginNotifyAction(OSObject *, void *, void *, void *, void *);
    static IOReturn finishNotifyAction(OSObject *, void *, void *, void *, void *);
    static IOReturn closeAction(OSObject *, void *, void *, void *, void *);
    static IOReturn finishCloseAction(OSObject *, void *, void *, void *, void *);
    static bool inGate(const Context &);
    bool matches(const Context &) const;
    bool rememberEmptyContext(const Context &);

    State state_ {State::Empty};
    // Keys are compared only, never dereferenced after owner references move
    // out. They prevent a stale generation from closing a different session.
    IOUserClient *clientKey_ {nullptr};
    IOWorkLoop *loopKey_ {nullptr};
    uint64_t generation_ {0};
    IOUserClient *clientOwner_ {nullptr};
    IOWorkLoop *loopOwner_ {nullptr};
    OSAsyncReference64 reference_ {};
    bool ownsRight_ {false};
    Snapshot counters_ {};
};

} // namespace AWDLKernel
#endif
