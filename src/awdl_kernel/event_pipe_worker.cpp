#include "event_pipe_worker.hpp"
#include "event_pipe_session.hpp"
#include <machine/machine_routines.h>

namespace AWDLKernel {
EventPipeWorker::State EventPipeWorker::state() const {
    return static_cast<State>(__atomic_load_n(&state_,__ATOMIC_ACQUIRE));
}
IOReturn EventPipeWorker::prepare(EventPipeSession &session,const ObserverHandle &binding) {
    if (!binding.client || !binding.generation) return kIOReturnBadArgument;
    if (ml_at_interrupt_context() || !ml_get_interrupts_enabled()) return kIOReturnNotPermitted;
    uint32_t expected=static_cast<uint32_t>(State::Empty);
    if (!__atomic_compare_exchange_n(&state_,&expected,static_cast<uint32_t>(State::Preparing),
            false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return kIOReturnNotReady;
    auto lock=IOSimpleLockAlloc();
    if (!lock) {
        __atomic_store_n(&state_,static_cast<uint32_t>(State::Stopped),__ATOMIC_RELEASE);
        return kIOReturnNoMemory;
    }
    auto call=thread_call_allocate_with_options(callback,this,
        THREAD_CALL_PRIORITY_KERNEL,THREAD_CALL_OPTIONS_ONCE);
    if (!call) {
        IOSimpleLockFree(lock); // Never published; no entrant can hold this lock.
        __atomic_store_n(&state_,static_cast<uint32_t>(State::Stopped),__ATOMIC_RELEASE);
        return kIOReturnNoMemory;
    }
    lock_=lock;call_=call;session_=&session;binding_=binding;
    __atomic_store_n(&published_,1U,__ATOMIC_RELEASE);
    expected=static_cast<uint32_t>(State::Preparing);
    if (!__atomic_compare_exchange_n(&state_,&expected,static_cast<uint32_t>(State::Armed),
            false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
        // beginClose raced initialization. No enter was allowed before Armed.
        __atomic_store_n(&state_,static_cast<uint32_t>(State::Stopped),__ATOMIC_RELEASE);
        return kIOReturnAborted;
    }
    __atomic_store_n(&successfulPrepare_,1U,__ATOMIC_RELEASE);
    return kIOReturnSuccess;
}
bool EventPipeWorker::matchesBinding(const ObserverHandle &binding) const {
    // Immutable after the release publication of Armed; never dereference keys.
    return state()==State::Armed && binding.client && binding.generation &&
        binding.client==binding_.client && binding.generation==binding_.generation;
}
bool EventPipeWorker::canReplaceBinding() const {
    // The successful-prepare release publishes this immutable pointer. Closed
    // is the old Session's terminal atomic phase; no owner/MD is dereferenced.
    // A late callback always uses session_, never an observer/router lookup.
    return __atomic_load_n(&successfulPrepare_,__ATOMIC_ACQUIRE) &&
        state()==State::Stopped && session_ &&
        session_->phase()==EventPipeCore::Phase::Closed;
}
EventPipeWorker::KickStatus EventPipeWorker::kickFromProducer(const ObserverHandle &binding) {
    if (state()!=State::Armed) return KickStatus::NotArmed;
    const auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    if (state()!=State::Armed) {
        IOSimpleLockUnlockEnableInterrupt(lock_,saved);return KickStatus::NotArmed;
    }
    if (binding.client!=binding_.client || binding.generation!=binding_.generation) {
        IOSimpleLockUnlockEnableInterrupt(lock_,saved);return KickStatus::Stale;
    }
    ++counters_.kicks;
    queued_=true;
    // Own lock serializes enter completion with close/cancel/poll. XNU ONCE
    // coalesces a running invocation into one reschedule, never overlap.
    const bool pending=thread_call_enter(call_);
    if (pending) ++counters_.coalesced;
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    return pending?KickStatus::Coalesced:KickStatus::Scheduled;
}
void EventPipeWorker::cancelLocked() {
    if (thread_call_cancel(call_)) {queued_=false;++counters_.cancelled;}
    // false is NOT "stopped". A dequeued callback must clear queued_ itself.
}
void EventPipeWorker::beginClose() {
    auto value=__atomic_load_n(&state_,__ATOMIC_ACQUIRE);
    for (;;) {
        const auto current=static_cast<State>(value);
        if (current==State::Stopped || current==State::PreparingClosing) return;
        if (current==State::Preparing) {
            if (__atomic_compare_exchange_n(&state_,&value,
                    static_cast<uint32_t>(State::PreparingClosing),false,
                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return;
            continue;
        }
        if (current==State::Empty) {
            if (__atomic_compare_exchange_n(&state_,&value,static_cast<uint32_t>(State::Stopped),
                    false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return;
            continue;
        }
        if (current==State::Closing) break;
        if (__atomic_compare_exchange_n(&state_,&value,static_cast<uint32_t>(State::Closing),
                false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) break;
    }
    const auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    cancelLocked();
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
}
IOReturn EventPipeWorker::pollStopped() {
    const auto current=state();
    if (current==State::Stopped) return kIOReturnSuccess;
    if (current!=State::Closing && current!=State::Faulted) return kIOReturnBusy;
    const auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    const bool stopped=!queued_ && !running_;
    if (stopped) __atomic_store_n(&state_,static_cast<uint32_t>(State::Stopped),__ATOMIC_RELEASE);
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    return stopped?kIOReturnSuccess:kIOReturnBusy;
}
EventPipeWorker::Snapshot EventPipeWorker::snapshot() const {
    Snapshot out;
    if (!__atomic_load_n(&published_,__ATOMIC_ACQUIRE)) {out.state=state();return out;}
    const auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    out=counters_;out.state=state();out.queued=queued_;out.running=running_;
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    return out;
}
void EventPipeWorker::callback(thread_call_param_t owner,thread_call_param_t) {
    static_cast<EventPipeWorker *>(owner)->run();
}
void EventPipeWorker::fault(EventPipeSession &session) {
    const auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    ++counters_.faults;
    // Do not reopen a close already requested by another caller.
    uint32_t expected=static_cast<uint32_t>(State::Armed);
    (void)__atomic_compare_exchange_n(&state_,&expected,static_cast<uint32_t>(State::Faulted),
        false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    cancelLocked();
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    session.beginClose(); // Atomic admission only; no resource release or wait.
}
void EventPipeWorker::run() {
    auto saved=IOSimpleLockLockDisableInterrupt(lock_);
    queued_=false;++counters_.callbacks;
    if (state()!=State::Armed) {
        IOSimpleLockUnlockEnableInterrupt(lock_,saved);return;
    }
    running_=true;
    auto &session=*session_;
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    bool progress=false,exhausted=true;
    for (uint32_t n=0;n<MaximumBatch;++n) {
        if (state()!=State::Armed) {exhausted=false;break;}
        // Outside every spin lock and old WL gate. Session's real core admits
        // an operation before it accesses owner/descriptors; close races fail.
        const auto result=session.drainOne();
        bool failed=false,stop=false;
        saved=IOSimpleLockLockDisableInterrupt(lock_);
        ++counters_.attempts;counters_.lastResult=result.result;
        counters_.lastNotification=result.notification;
        if (result.codecAttempted) {
            uint64_t *received=&counters_.receivedOther,*rejected=&counters_.rejectedOther;
            if (result.message==46) {received=&counters_.received46;rejected=&counters_.rejected46;}
            else if (result.message==47) {received=&counters_.received47;rejected=&counters_.rejected47;}
            else if (result.message==48) {received=&counters_.received48;rejected=&counters_.rejected48;}
            ++*received;
            counters_.lastCodecMessage=result.message;counters_.lastCodecError=result.codecError;
            if (result.codecError) {
                ++*rejected;
                if (result.message==48) {
                    counters_.last48RejectMask=result.codecRejectMask;
                    counters_.seen48RejectMask|=result.codecRejectMask;
                }
            }
        }
        if (result.result==kIOReturnNotFound) {++counters_.empty;stop=true;}
        else if (result.result==kIOReturnBusy) {++counters_.busy;stop=true;}
        else if (result.result==kIOReturnNotReady) {++counters_.notReady;stop=true;}
        else if (result.result==kIOReturnUnsupported && result.dropped==1 &&
                 !result.committed && !result.full) {++counters_.dropped;progress=true;}
        else if (result.result==kIOReturnSuccess && result.committed<=1 && result.full<=1 &&
                 result.committed+result.full==1 && result.dropped==result.full) {
            counters_.committed+=result.committed;counters_.full+=result.full;
            counters_.dropped+=result.dropped;progress=true;
            if (result.codecAttempted && result.committed) {
                uint64_t *committed=&counters_.committedOther;
                if (result.message==46) committed=&counters_.committed46;
                else if (result.message==47) committed=&counters_.committed47;
                else if (result.message==48) committed=&counters_.committed48;
                ++*committed;
            }
            // A committed/full record is not replayed, even when notify fails.
            failed=result.notification!=kIOReturnSuccess;
        } else failed=true;
        IOSimpleLockUnlockEnableInterrupt(lock_,saved);
        if (failed) {fault(session);exhausted=false;break;}
        if (stop) {exhausted=false;break;}
    }
    saved=IOSimpleLockLockDisableInterrupt(lock_);
    // Only a full batch of real consumed snapshots self-rearms. Busy/NotReady
    // park until a genuine producer/owner progress kick; no timer/poll loop.
    if (state()==State::Armed && exhausted && progress && !queued_) {
        queued_=true;++counters_.rearmed;(void)thread_call_enter(call_);
    }
    running_=false;
    IOSimpleLockUnlockEnableInterrupt(lock_,saved);
    // No subsequent access to Session or descriptors. Resident return tail.
}
}
