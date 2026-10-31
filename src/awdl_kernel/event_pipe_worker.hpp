// Default-unwired, resident thread-call consumer. No hook or ready assertion.
#ifndef AIRPORT_AWDL_EVENT_PIPE_WORKER_HPP
#define AIRPORT_AWDL_EVENT_PIPE_WORKER_HPP
#include <IOKit/IOLocks.h>
#include <IOKit/IOReturn.h>
#include <kern/thread_call.h>
#include "legacy_post_observer_core.hpp"

namespace AWDLKernel {
class EventPipeSession;
class EventPipeWorker final {
public:
    enum class State : uint32_t {
        Empty, Preparing, PreparingClosing, Armed, Closing, Faulted, Stopped
    };
    enum class KickStatus : uint32_t { Scheduled, Coalesced, NotArmed, Stale };
    static constexpr uint32_t MaximumBatch=16;
    struct Snapshot {
        State state=State::Empty;
        uint32_t queued=0,running=0;
        uint64_t kicks=0,coalesced=0,callbacks=0,attempts=0;
        uint64_t committed=0,dropped=0,full=0,empty=0,busy=0,notReady=0;
        uint64_t rearmed=0,faults=0,cancelled=0;
        IOReturn lastResult=kIOReturnNotReady,lastNotification=kIOReturnNotReady;
        // Actual codec attempts only, not empty callbacks or wake counts.
        // A rejected body is distinct from a full ring or failed notification.
        uint64_t received46=0,received47=0,received48=0,receivedOther=0;
        uint64_t rejected46=0,rejected47=0,rejected48=0,rejectedOther=0;
        uint64_t committed46=0,committed47=0,committed48=0,committedOther=0;
        uint32_t lastCodecMessage=0,lastCodecError=0,last48RejectMask=0,seen48RejectMask=0;
    };
    EventPipeWorker()=default;
    EventPipeWorker(const EventPipeWorker &)=delete;
    EventPipeWorker &operator=(const EventPipeWorker &)=delete;

    // ALL STORAGE IS STATIC/RESIDENT UNTIL REBOOT. No implicit destructor,
    // free, reset, replacement or rebinding. Neither cancel nor pollStopped
    // is a physical producer-entry barrier or permission to reclaim storage.
    // Even a cancelled prepare retains any successfully allocated thread call.
    // Session/backend/registry storage also remains resident. Actual session
    // core admission, not this pointer or generation, protects live resources.

    // IRQ-safe; no allocation, gate entry, IPC, payload copy or Session access.
    // Call AFTER releasing observer/queue locks. Only the genuine bound queue
    // may issue this handle; the numeric key itself is not authorization.
    KickStatus kickFromProducer(const ObserverHandle &);
    // IRQ-safe immutable-key comparison; false after close admission stops.
    bool matchesBinding(const ObserverHandle &) const;
    // IRQ-safe permission for the observer to replace its typed pointer after
    // an actual Halt -> same-connection Open path has separately authorized a
    // NEW resident Session. True only after a successful prepare, Stopped,
    // and this worker's immutable OLD Session has completed resource close.
    // Does not rebind this worker, reset observer serials, free storage, or
    // authorize a new connection/generation by itself.
    bool canReplaceBinding() const;
    // IRQ-safe, non-waiting. Stops admission and cancels pending/rescheduled
    // work. A cancel=false can mean dequeued but not yet entered: preserve its
    // queued marker until that callback arrives and observes Closing.
    void beginClose();
    // Non-waiting. Success means no callback can still access Session/MDs.
    // A callback's final return epilogue can still run on resident storage.
    // Caller first stops new capture; Session keeps resources until Success.
    IOReturn pollStopped();
    Snapshot snapshot() const;
private:
    friend class EventPipeSession;
    // Sleepable, outside the captured WL gate. ONLY the real Session may bind
    // its own subscribe-produced handle before publishing its worker binding.
    // A failed prepare is terminal; no thread-call free or storage reuse.
    IOReturn prepare(EventPipeSession &,const ObserverHandle &);
    static void callback(thread_call_param_t,thread_call_param_t);
    void run();
    void fault(EventPipeSession &);
    State state() const;
    void cancelLocked();
    uint32_t state_=static_cast<uint32_t>(State::Empty),published_=0,successfulPrepare_=0;
    IOSimpleLock *lock_=nullptr;
    thread_call_t call_=nullptr;
    EventPipeSession *session_=nullptr;
    ObserverHandle binding_ {};
    bool queued_=false,running_=false;
    Snapshot counters_ {};
};
}
#endif
