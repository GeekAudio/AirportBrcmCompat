#include "async_notification_owner.hpp"
#include <machine/machine_routines.h>
#include <string.h>

#if !defined(__x86_64__)
#error "The pinned native async registration is x86_64 only"
#endif

namespace AWDLKernel { namespace {
class AsyncKPIAccess : public IOUserClient {
public:
    using IOUserClient::sendAsyncResult64;
};
static_assert(kOSAsyncRef64Count == 8, "Native selector2 reference count");
static_assert(sizeof(OSAsyncReference64) == 64, "Native selector2 reference bytes");
static_assert(sizeof(mach_port_t) == sizeof(uintptr_t), "Kernel port, not user port name");

bool sleepable() {
    return !ml_at_interrupt_context() && ml_get_interrupts_enabled();
}
bool subscriptionShape(const IOExternalMethodArguments &a) {
    if (a.version != 2 || a.selector != 2 || a.scalarInputCount || a.scalarOutputCount ||
        a.structureInputSize || a.structureOutputSize || a.structureInputDescriptor ||
        a.structureOutputDescriptor || a.structureOutputDescriptorSize ||
        a.structureVariableOutputData || a.asyncReferenceCount != kOSAsyncRef64Count ||
        !a.asyncReference || a.asyncWakePort == MACH_PORT_NULL) return false;
    // Actual 64-bit MIG overwrites ref[0] with this kernel port | 1. Neither
    // this value nor the callback/refcon entries are probed or dereferenced.
    const uintptr_t wake = reinterpret_cast<uintptr_t>(a.asyncWakePort);
    return !(wake & 3U) && a.asyncReference[0] == (wake | 1U);
}
void clearReference(OSAsyncReference64 &reference) {
    memset(reference, 0, sizeof(reference));
}
} // namespace

bool AsyncNotificationOwner::inGate(const Context &c) {
    return c.client && c.loop && c.generation && sleepable() && c.loop->inGate();
}
bool AsyncNotificationOwner::matches(const Context &c) const {
    return c.client == clientKey_ && c.loop == loopKey_ && c.generation == generation_;
}
bool AsyncNotificationOwner::rememberEmptyContext(const Context &c) {
    if (state_ != State::Empty) return matches(c);
    // Closing an empty owner adopts no rights/references and must still work
    // after client inactivity. Only the genuine serial caller lease is needed.
    clientKey_ = c.client; loopKey_ = c.loop; generation_ = c.generation;
    return true;
}

IOReturn AsyncNotificationOwner::adoptFromSuccessfulDispatch(
    const Context &c, const IOExternalMethodArguments &a) {
    if (!inGate(c)) return kIOReturnNotReady;
    if (state_ != State::Empty) return matches(c) && state_ == State::Subscribed
        ? kIOReturnBusy : kIOReturnNotOpen;
    if (c.client->isInactive() || c.client->getWorkLoop() != c.loop)
        return kIOReturnNotReady;
    if (!subscriptionShape(a)) return kIOReturnBadArgument;

    // Every check precedes adoption. No call/failure follows publication.
    // The caller's final RPC Success is the ownership commit; memcpy alone
    // cannot convert a failed MIG call into an owned send right.
    c.client->retain(); c.loop->retain();
    clientOwner_ = c.client; loopOwner_ = c.loop;
    clientKey_ = c.client; loopKey_ = c.loop; generation_ = c.generation;
    memcpy(reference_, a.asyncReference, sizeof(reference_));
    ownsRight_ = true; state_ = State::Subscribed; ++counters_.adopted;
    return kIOReturnSuccess;
}

struct AsyncNotificationOwner::NotifyCall {
    AsyncNotificationOwner *owner;
    Context context;
    OSAsyncReference64 reference {};
    bool admitted {false};
    IOReturn sendResult {kIOReturnNotReady};
};

IOReturn AsyncNotificationOwner::beginNotifyAction(OSObject *, void *argument,
                                                  void *, void *, void *) {
    auto &call = *static_cast<NotifyCall *>(argument);
    auto &s = *call.owner;
    if (!inGate(call.context) || !s.matches(call.context)) return kIOReturnNotReady;
    if (s.state_ != State::Subscribed || !s.ownsRight_) return kIOReturnNotOpen;
    if (s.counters_.inFlight) return kIOReturnBusy;
    if (call.context.client->isInactive() ||
        call.context.client->getWorkLoop() != call.context.loop) return kIOReturnNotReady;
    memcpy(call.reference, s.reference_, sizeof(call.reference));
    s.counters_.inFlight = 1; ++s.counters_.notifyAttempts;
    call.admitted = true;
    return kIOReturnSuccess;
}

IOReturn AsyncNotificationOwner::finishNotifyAction(OSObject *, void *argument,
                                                   void *, void *, void *) {
    auto &call = *static_cast<NotifyCall *>(argument);
    auto &s = *call.owner;
    // Inactive/Closing is deliberately allowed for admitted work to drain.
    if (!inGate(call.context) || !s.matches(call.context) || !call.admitted ||
        s.counters_.inFlight != 1 || !s.ownsRight_ ||
        (s.state_ != State::Subscribed && s.state_ != State::Closing))
        return kIOReturnInternalError;
    s.counters_.inFlight = 0; s.counters_.lastSend = call.sendResult;
    // The KPI may set its private "error logged" flag on our local copy.
    // Preserve that one flag without replacing the owned port/callback data.
    s.reference_[0] |= call.reference[0] & 2U;
    if (call.sendResult == kIOReturnSuccess) ++s.counters_.notifySucceeded;
    else ++s.counters_.notifyFailed;
    call.admitted = false;
    return kIOReturnSuccess;
}

IOReturn AsyncNotificationOwner::notifyZeroArgs(const Context &c) {
    if (!c.client || !c.loop || !c.generation || !sleepable() || c.loop->inGate())
        return kIOReturnNotReady;
    // Genuine caller leases cover entry. These extra temporary references
    // cover our complete begin/send/finish dynamic extent, independent of IPC.
    c.client->retain(); c.loop->retain();
    NotifyCall call {this, c};
    const auto admitted = c.loop->runAction(beginNotifyAction, c.client, &call);
    IOReturn result = admitted;
    if (admitted == kIOReturnSuccess) {
        call.sendResult = AsyncKPIAccess::sendAsyncResult64(call.reference,
            kIOReturnSuccess, nullptr, 0);
        const auto finished = c.loop->runAction(finishNotifyAction, c.client, &call);
        result = finished == kIOReturnSuccess ? call.sendResult : finished;
        // An impossible failed completion deliberately leaves inFlight set:
        // close stays Busy; no forced release of a possibly still-used right.
    }
    clearReference(call.reference);
    c.client->release(); c.loop->release();
    return result;
}

IOReturn AsyncNotificationOwner::beginClose(const Context &c) {
    if (!inGate(c) || !rememberEmptyContext(c)) return kIOReturnNotReady;
    if (state_ == State::Empty) state_ = State::Closed;
    else if (state_ == State::Subscribed) state_ = State::Closing;
    return kIOReturnSuccess;
}

struct AsyncNotificationOwner::CloseCall {
    AsyncNotificationOwner *owner;
    Context context;
    IOUserClient *client {nullptr};
    IOWorkLoop *loop {nullptr};
    OSAsyncReference64 reference {};
    bool right {false};
    IOReturn released {kIOReturnSuccess};
};

IOReturn AsyncNotificationOwner::closeAction(OSObject *, void *argument,
                                            void *, void *, void *) {
    auto &call = *static_cast<CloseCall *>(argument);
    auto &s = *call.owner;
    const auto started = s.beginClose(call.context);
    if (started != kIOReturnSuccess) return started;
    if (s.state_ == State::Closed) return s.counters_.lastRelease;
    if (s.state_ == State::Retiring) return kIOReturnBusy;
    if (s.counters_.inFlight) return kIOReturnBusy;
    if (!s.ownsRight_ || !s.clientOwner_ || !s.loopOwner_)
        return kIOReturnInternalError;
    // No sends can newly enter Closing; an admitted sender keeps inFlight=1.
    memcpy(call.reference, s.reference_, sizeof(call.reference));
    call.right = true; call.client = s.clientOwner_; call.loop = s.loopOwner_;
    clearReference(s.reference_); s.ownsRight_ = false;
    s.clientOwner_ = nullptr; s.loopOwner_ = nullptr; s.state_ = State::Retiring;
    ++s.counters_.releaseAttempts;
    return kIOReturnSuccess;
}

IOReturn AsyncNotificationOwner::finishCloseAction(OSObject *, void *argument,
                                                  void *, void *, void *) {
    auto &call = *static_cast<CloseCall *>(argument);
    auto &s = *call.owner;
    if (!inGate(call.context) || !s.matches(call.context) ||
        s.state_ != State::Retiring || s.ownsRight_ || s.clientOwner_ ||
        s.loopOwner_ || s.counters_.inFlight) return kIOReturnInternalError;
    s.counters_.lastRelease = call.released;
    s.state_ = State::Closed;
    return kIOReturnSuccess;
}

IOReturn AsyncNotificationOwner::close(const Context &c) {
    if (!c.client || !c.loop || !c.generation || !sleepable() || c.loop->inGate())
        return kIOReturnNotReady;
    CloseCall call {this, c};
    const auto result = c.loop->runAction(closeAction, c.client, &call);
    if (result != kIOReturnSuccess) return result;
    if (!call.right) return kIOReturnSuccess;
    call.released = IOUserClient::releaseAsyncReference64(call.reference);
    clearReference(call.reference);
    if (call.client) call.client->release();
    if (call.loop) call.loop->release();
    const auto finished = c.loop->runAction(finishCloseAction, c.client, &call);
    // The real KPI returns Success. Preserve an unexpected error across repeat
    // close calls, without retrying its ambiguous send-right consumption.
    return finished == kIOReturnSuccess ? call.released : finished;
}

IOReturn AsyncNotificationOwner::snapshotInGate(const Context &c, Snapshot &out) const {
    out = {};
    if (!inGate(c) || (state_ != State::Empty && !matches(c))) return kIOReturnNotReady;
    out = counters_; out.state = state_;
    return kIOReturnSuccess;
}

} // namespace AWDLKernel
