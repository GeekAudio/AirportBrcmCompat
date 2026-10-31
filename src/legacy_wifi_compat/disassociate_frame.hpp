// Pure state machine for the narrowly scoped legacy disassociation IE route.
// The adapter owns every kernel operation and every raw-address access.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_FRAME_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_FRAME_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi {
namespace DisassociateFrame {

constexpr size_t ReasonIEBytes = 13;
constexpr size_t ReasonIEAppendOffset = 2;
constexpr uint32_t OriginalReasonBytes = 2;
constexpr uint32_t ExtendedBodyBytes = 15;
constexpr uint16_t DisassociateSubtype = 0xa0;
constexpr size_t MaximumNestedScopes = 8;
constexpr size_t MaximumNestedSenders = 8;

enum class DriverKind : uint8_t { Invalid, Brcm4331, Brcm43224 };

enum class Status : uint8_t {
    InvalidArgument,
    ContextUnavailable,
    Pending,
    NotMatched,
    LeaseActive,
    Enhanced,
    BuilderFailed,
    WriteFailed,
    OwnerStale,
    ContractViolation
};

struct MacAddress {
    uint8_t bytes[6] {};
};

inline bool sameAddress(const MacAddress &left, const MacAddress &right) {
    return memcmp(left.bytes, right.bytes, sizeof(left.bytes)) == 0;
}

inline bool validBSSID(const MacAddress &address) {
    uint8_t aggregate = 0;
    for (size_t index = 0; index < sizeof(address.bytes); ++index)
        aggregate |= address.bytes[index];
    return aggregate != 0 && (address.bytes[0] & 1U) == 0;
}

// Encodes the exact 13-byte vendor IE. `reason` is serialized as a full
// uint32_t little-endian value; it is never narrowed to the 16-bit frame field.
inline bool encodeReasonIE(uint32_t reason, uint8_t *output, size_t outputSize) {
    if (!output || outputSize < ReasonIEBytes) return false;
    const uint8_t prefix[9] = {0xdd, 0x0b, 0x00, 0x17, 0xf2,
                               0x0a, 0x02, 0x01, 0x04};
    memcpy(output, prefix, sizeof(prefix));
    output[9] = static_cast<uint8_t>(reason);
    output[10] = static_cast<uint8_t>(reason >> 8);
    output[11] = static_cast<uint8_t>(reason >> 16);
    output[12] = static_cast<uint8_t>(reason >> 24);
    return true;
}

struct HookContract {
    DriverKind driver = DriverKind::Invalid;
    uintptr_t senderCallerPCs[2] {};
    uint8_t senderCallerPCCount = 0;
    uintptr_t builderReturnPC = 0;
};

inline HookContract pinnedElCap4331Contract() {
    HookContract contract {};
    contract.driver = DriverKind::Brcm4331;
    contract.senderCallerPCs[0] = 0xb0dc5;
    contract.senderCallerPCs[1] = 0xb0e40;
    contract.senderCallerPCCount = 2;
    contract.builderReturnPC = 0x4d77c;
    return contract;
}

inline HookContract pinnedElCap43224Contract() {
    HookContract contract {};
    contract.driver = DriverKind::Brcm43224;
    contract.senderCallerPCs[0] = 0x67790;
    contract.senderCallerPCCount = 1;
    contract.builderReturnPC = 0x7e4a4;
    return contract;
}

inline bool validContract(const HookContract &contract, DriverKind driver) {
    if (driver == DriverKind::Invalid || contract.driver != driver ||
        !contract.builderReturnPC || contract.senderCallerPCCount == 0 ||
        contract.senderCallerPCCount > 2 || !contract.senderCallerPCs[0]) return false;
    if (contract.senderCallerPCCount == 2 &&
        (!contract.senderCallerPCs[1] ||
         contract.senderCallerPCs[0] == contract.senderCallerPCs[1])) return false;
    return true;
}

struct SenderInvocation {
    DriverKind driver = DriverKind::Invalid;
    uintptr_t callerReturnPC = 0;
    void *wlc = nullptr;
    const void *address3 = nullptr;
    void *scb = nullptr;
    uint32_t reason = 0;
    void *opaque = nullptr;
};

struct BuilderInvocation {
    DriverKind driver = DriverKind::Invalid;
    uintptr_t callerReturnPC = 0;
    void *wlc = nullptr;
    const void *address3 = nullptr;
    uint16_t subtype = 0;
    uint32_t bodyLength = 0;
    void *bodyOutSlot = nullptr;
    void *opaque = nullptr;
};

struct Callbacks {
    void *context = nullptr;
    uintptr_t (*currentThread)(void *context) = nullptr;
    bool (*ownerGenerationCurrent)(void *context, const void *owner,
                                   uint64_t requestID,
                                   uint64_t ownerGeneration) = nullptr;
    // The core never dereferences address3. The adapter validates and copies
    // the six bytes into this owned value.
    bool (*readAddress3)(void *context, DriverKind driver,
                         const void *address3, MacAddress *output) = nullptr;
    void *(*originalSender)(void *context,
                            const SenderInvocation &invocation) = nullptr;
    // Must invoke the exact original builder with every argument unchanged
    // except bodyLength, which the core may set to ExtendedBodyBytes.
    void *(*originalBuilder)(void *context,
                             const BuilderInvocation &invocation) = nullptr;
    // Must validate/read bodyOutSlot and atomically copy all bytes at offset.
    // On false, it must leave the destination bytes unchanged.
    bool (*writeBodyBytes)(void *context, DriverKind driver,
                           void *bodyOutSlot, size_t offset,
                           const uint8_t *bytes, size_t length) = nullptr;
    // Called only for an originalBuilder success still owned before returning
    // to the sender, after a stale/violated scope or failed write. Release that
    // mbuf once; neither a queued packet nor a null builder result belongs here.
    void (*freeUnqueuedPacket)(void *context, DriverKind driver,
                               void *wlc, void *packet) = nullptr;
};

class RouteContext;
class RequestScope;
struct RouteResult;
RouteResult interceptSender(RouteContext &context,
                            const SenderInvocation &invocation,
                            const Callbacks &callbacks);
RouteResult interceptBuilder(RouteContext &context,
                             const BuilderInvocation &invocation,
                             const Callbacks &callbacks);

// A RouteContext is an explicit, caller-owned synchronous stack. It is not
// global and is not internally thread-safe. Its owner must serialize access,
// keep it alive through the wrapped setter/sender/builder calls, and provide
// the context selected for the current thread. The runtime registry is
// responsible for finding the right context.
class RouteContext {
public:
    RouteContext() = default;
    RouteContext(const RouteContext &) = delete;
    RouteContext &operator=(const RouteContext &) = delete;
    RouteContext(RouteContext &&) = delete;
    RouteContext &operator=(RouteContext &&) = delete;

private:
    friend class RequestScope;
    friend struct RouteAccess;
    friend RouteResult interceptSender(RouteContext &context,
                                       const SenderInvocation &invocation,
                                       const Callbacks &callbacks);
    friend RouteResult interceptBuilder(RouteContext &context,
                                        const BuilderInvocation &invocation,
                                        const Callbacks &callbacks);

    struct SenderFrame {
        RequestScope *scope = nullptr;
        uint64_t leaseID = 0;
        uintptr_t thread = 0;
        bool active = false;
        bool matchingSender = false;
        bool armed = false;
        bool builderSeen = false;
        bool packetExtended = false;
    };

    RequestScope *scopes_[MaximumNestedScopes] {};
    size_t scopeDepth_ = 0;
    SenderFrame senders_[MaximumNestedSenders] {};
    size_t senderDepth_ = 0;
    uintptr_t boundThread_ = 0;
    uint64_t nextLeaseID_ = 1;
};

class RequestScope {
public:
    RequestScope(RouteContext &context, const HookContract &contract,
                 DriverKind driver, const void *owner, uint64_t requestID,
                 uint64_t ownerGeneration, void *wlc,
                 const MacAddress &bssid, uint32_t extendedReason,
                 const Callbacks &callbacks)
        : context_(&context), contract_(contract), driver_(driver),
          owner_(owner), requestID_(requestID),
          ownerGeneration_(ownerGeneration), wlc_(wlc), bssid_(bssid),
          extendedReason_(extendedReason) {
        if (!validContract(contract_, driver_) || !owner_ || !requestID_ ||
            !ownerGeneration_ || !wlc_ || !validBSSID(bssid_) ||
            !extendedReason_ ||
            !callbacks.currentThread || !callbacks.ownerGenerationCurrent) {
            status_ = Status::InvalidArgument;
            context_ = nullptr;
            return;
        }
        thread_ = callbacks.currentThread(callbacks.context);
        if (!thread_ || !callbacks.ownerGenerationCurrent(
                callbacks.context, owner_, requestID_, ownerGeneration_)) {
            status_ = Status::OwnerStale;
            context_ = nullptr;
            return;
        }
        if (!pushScope(context, this, thread_)) {
            status_ = violated_ ? Status::ContractViolation : Status::ContextUnavailable;
            context_ = nullptr;
            return;
        }
        active_ = true;
        status_ = Status::Pending;
    }

    ~RequestScope() {
        if (!context_) return;
        if (leaseActive_) markViolation();
        active_ = false;
        popScope(*context_, this);
        context_ = nullptr;
    }

    RequestScope(const RequestScope &) = delete;
    RequestScope &operator=(const RequestScope &) = delete;
    RequestScope(RequestScope &&) = delete;
    RequestScope &operator=(RequestScope &&) = delete;

    bool active() const { return active_; }
    // True only when IE construction completed without a contract violation.
    // It does not imply that the packet was queued or transmitted.
    bool complete() const { return active_ && status_ == Status::Enhanced && !violated_; }
    Status status() const { return status_; }
    DriverKind driver() const { return driver_; }
    uintptr_t thread() const { return thread_; }
    const void *owner() const { return owner_; }
    uint64_t requestID() const { return requestID_; }
    uint64_t ownerGeneration() const { return ownerGeneration_; }
    void *wlc() const { return wlc_; }
    const MacAddress &bssid() const { return bssid_; }
    uint32_t extendedReason() const { return extendedReason_; }

private:
    friend class RouteContext;
    friend struct RouteAccess;
    friend RouteResult interceptSender(RouteContext &context,
                                       const SenderInvocation &invocation,
                                       const Callbacks &callbacks);
    friend RouteResult interceptBuilder(RouteContext &context,
                                        const BuilderInvocation &invocation,
                                        const Callbacks &callbacks);

    enum class Phase : uint8_t { Invalid, Ready, Leased, Building, Finished, Closed };

    RouteContext *context_ = nullptr;
    HookContract contract_ {};
    DriverKind driver_ = DriverKind::Invalid;
    uintptr_t thread_ = 0;
    const void *owner_ = nullptr;
    uint64_t requestID_ = 0;
    uint64_t ownerGeneration_ = 0;
    void *wlc_ = nullptr;
    MacAddress bssid_ {};
    uint32_t extendedReason_ = 0;
    uint64_t leaseID_ = 0;
    Status status_ = Status::InvalidArgument;
    Phase phase_ = Phase::Invalid;
    bool active_ = false;
    bool leaseActive_ = false;
    bool violated_ = false;

    static bool pushScope(RouteContext &context, RequestScope *scope,
                          uintptr_t thread);
    static void popScope(RouteContext &context, RequestScope *scope);
    static RequestScope *topScope(RouteContext &context, uintptr_t thread);
    static bool pushSender(RouteContext &context,
                           const RouteContext::SenderFrame &frame);
    static void popSender(RouteContext &context,
                          RouteContext::SenderFrame *frame);
    static RouteContext::SenderFrame *topSender(RouteContext &context,
                                                uintptr_t thread);

    void markViolation() {
        violated_ = true;
        // A violation before builder consumption cancels the pending change.
        // A lease already consumed by a successful write is left alone: its
        // sender frame records the bytes actually appended to that packet.
        cancelUnusedLease();
        if (status_ != Status::OwnerStale)
            status_ = Status::ContractViolation;
    }

    void markOwnerStale() {
        violated_ = true;
        cancelUnusedLease();
        phase_ = Phase::Invalid;
        status_ = Status::OwnerStale;
    }

    void cancelUnusedLease() {
        if (!leaseActive_) return;
        leaseActive_ = false;
        if (!context_) return;
        for (size_t index = 0; index < context_->senderDepth_; ++index) {
            RouteContext::SenderFrame &frame = context_->senders_[index];
            if (frame.scope == this && frame.leaseID == leaseID_)
                frame.armed = false;
        }
    }

    void markStatus(Status status) {
        if (!violated_) status_ = status;
    }

    void consumeLease(RouteContext::SenderFrame &frame) {
        if (leaseActive_ && frame.leaseID == leaseID_) leaseActive_ = false;
        frame.armed = false;
        frame.builderSeen = true;
    }
};

inline bool RequestScope::pushScope(RouteContext &context, RequestScope *scope,
                                    uintptr_t thread) {
    if (!scope || !thread || context.scopeDepth_ >= MaximumNestedScopes ||
        (context.boundThread_ && context.boundThread_ != thread)) return false;
    for (size_t index = 0; index < context.scopeDepth_; ++index) {
        RequestScope *existing = context.scopes_[index];
        if (existing && existing->active_ && existing->owner_ == scope->owner_ &&
            existing->requestID_ == scope->requestID_ &&
            existing->ownerGeneration_ == scope->ownerGeneration_) {
            existing->markViolation();
            scope->markViolation();
            return false;
        }
    }
    context.boundThread_ = thread;
    context.scopes_[context.scopeDepth_++] = scope;
    scope->phase_ = Phase::Ready;
    return true;
}

inline void RequestScope::popScope(RouteContext &context, RequestScope *scope) {
    for (size_t index = 0; index < context.senderDepth_;) {
        if (context.senders_[index].scope != scope) {
            ++index;
            continue;
        }
        for (size_t move = index + 1; move < context.senderDepth_; ++move)
            context.senders_[move - 1] = context.senders_[move];
        context.senders_[--context.senderDepth_] = RouteContext::SenderFrame {};
    }
    for (size_t index = 0; index < context.scopeDepth_; ++index) {
        if (context.scopes_[index] != scope) continue;
        for (size_t move = index + 1; move < context.scopeDepth_; ++move)
            context.scopes_[move - 1] = context.scopes_[move];
        context.scopes_[--context.scopeDepth_] = nullptr;
        break;
    }
    if (!context.scopeDepth_) context.boundThread_ = 0;
    scope->phase_ = Phase::Closed;
    scope->leaseActive_ = false;
}

inline RequestScope *RequestScope::topScope(RouteContext &context,
                                            uintptr_t thread) {
    if (!thread || context.boundThread_ != thread || !context.scopeDepth_)
        return nullptr;
    RequestScope *scope = context.scopes_[context.scopeDepth_ - 1];
    return scope && scope->active_ && scope->thread_ == thread ? scope : nullptr;
}

inline bool RequestScope::pushSender(
        RouteContext &context, const RouteContext::SenderFrame &frame) {
    if (context.senderDepth_ >= MaximumNestedSenders) return false;
    context.senders_[context.senderDepth_++] = frame;
    return true;
}

inline void RequestScope::popSender(RouteContext &context,
                                    RouteContext::SenderFrame *frame) {
    if (!frame) return;
    size_t index = context.senderDepth_;
    while (index && &context.senders_[index - 1] != frame) --index;
    if (!index) return;
    --index;
    for (size_t move = index + 1; move < context.senderDepth_; ++move)
        context.senders_[move - 1] = context.senders_[move];
    context.senders_[--context.senderDepth_] = RouteContext::SenderFrame {};
}

inline RouteContext::SenderFrame *RequestScope::topSender(
        RouteContext &context, uintptr_t thread) {
    if (!thread || context.boundThread_ != thread || !context.senderDepth_)
        return nullptr;
    RouteContext::SenderFrame *frame = &context.senders_[context.senderDepth_ - 1];
    return frame->active && frame->thread == thread ? frame : nullptr;
}

struct RouteAccess {
    static RequestScope *topScope(RouteContext &context, uintptr_t thread) {
        return RequestScope::topScope(context, thread);
    }
    static RouteContext::SenderFrame *topSender(RouteContext &context,
                                                uintptr_t thread) {
        return RequestScope::topSender(context, thread);
    }
};

struct RouteResult {
    void *packet = nullptr;
    Status status = Status::NotMatched;
    bool matched = false;
    // For sender results, this reports whether a packet built during this
    // sender call actually received the IE. It is independent of request
    // completion and does not imply that the native sender returned the
    // packet, queued it, or transmitted it.
    bool extended = false;
};

inline bool senderPCMatches(const HookContract &contract, uintptr_t pc) {
    for (size_t index = 0; index < contract.senderCallerPCCount; ++index)
        if (contract.senderCallerPCs[index] == pc) return true;
    return false;
}

inline bool callbacksForSender(const Callbacks &callbacks) {
    return callbacks.currentThread && callbacks.ownerGenerationCurrent &&
        callbacks.readAddress3 && callbacks.originalSender;
}

inline bool callbacksForBuilder(const Callbacks &callbacks) {
    return callbacks.currentThread && callbacks.ownerGenerationCurrent &&
        callbacks.readAddress3 && callbacks.originalBuilder &&
        callbacks.writeBodyBytes && callbacks.freeUnqueuedPacket;
}

inline RouteResult interceptSender(RouteContext &context,
                                   const SenderInvocation &invocation,
                                   const Callbacks &callbacks) {
    RouteResult result {};
    if (!callbacks.originalSender) {
        result.status = Status::InvalidArgument;
        return result;
    }
    const uintptr_t thread = callbacks.currentThread
        ? callbacks.currentThread(callbacks.context) : 0;
    RequestScope *scope = RequestScope::topScope(context, thread);
    if (!scope) {
        result.packet = callbacks.originalSender(callbacks.context, invocation);
        result.status = Status::NotMatched;
        return result;
    }

    RouteContext::SenderFrame frame {};
    frame.scope = scope;
    frame.thread = thread;
    frame.active = true;

    MacAddress address3 {};
    const bool identityMatch = callbacksForSender(callbacks) &&
        thread == scope->thread_ && invocation.driver == scope->driver_ &&
        invocation.driver == scope->contract_.driver &&
        invocation.callerReturnPC &&
        senderPCMatches(scope->contract_, invocation.callerReturnPC) &&
        invocation.wlc == scope->wlc_ && invocation.address3 &&
        callbacks.readAddress3(callbacks.context, invocation.driver,
                               invocation.address3, &address3) &&
        sameAddress(address3, scope->bssid_);
    const bool ownerCurrent = identityMatch &&
        callbacks.ownerGenerationCurrent(callbacks.context, scope->owner_,
                                         scope->requestID_,
                                         scope->ownerGeneration_);
    const bool basicMatch = identityMatch && ownerCurrent;
    if (identityMatch && !ownerCurrent) scope->markOwnerStale();

    if (basicMatch) {
        frame.matchingSender = true;
        result.matched = true;
        if (scope->phase_ == RequestScope::Phase::Ready &&
            !scope->leaseActive_ && !scope->violated_) {
            frame.leaseID = context.nextLeaseID_++;
            if (!frame.leaseID) frame.leaseID = context.nextLeaseID_++;
            frame.armed = true;
            scope->leaseID_ = frame.leaseID;
            scope->leaseActive_ = true;
            scope->phase_ = RequestScope::Phase::Leased;
            scope->markStatus(Status::LeaseActive);
        } else {
            // A nested matching sender is passed through without replacing or
            // consuming the outer lease. A sequential duplicate is reported
            // the same way; neither can silently claim an enhanced result.
            scope->markViolation();
        }
    }

    if (!RequestScope::pushSender(context, frame)) {
        // No nested slot is available to shield an outer sender. Invalidate
        // every in-flight scope represented in this context before passing
        // through, so the nested builder cannot be mistaken for an outer one.
        for (size_t index = 0; index < context.senderDepth_; ++index) {
            RouteContext::SenderFrame &active = context.senders_[index];
            if (active.scope) active.scope->markViolation();
            active.armed = false;
        }
        scope->markViolation();
        result.packet = callbacks.originalSender(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    RouteContext::SenderFrame *activeFrame =
        &context.senders_[context.senderDepth_ - 1];
    result.packet = callbacks.originalSender(callbacks.context, invocation);
    if (activeFrame->armed && scope->leaseActive_ &&
        activeFrame->leaseID == scope->leaseID_) {
        scope->markViolation(); // expected direct builder call was not consumed
    }
    result.status = scope->status_;
    // Report the bytes actually added to this sender's packet, independently
    // from request completion. A later duplicate can invalidate the scope
    // without undoing a packet that was already extended.
    result.extended = activeFrame->packetExtended;
    RequestScope::popSender(context, activeFrame);
    return result;
}

inline RouteResult interceptBuilder(RouteContext &context,
                                    const BuilderInvocation &invocation,
                                    const Callbacks &callbacks) {
    RouteResult result {};
    if (!callbacks.originalBuilder) {
        result.status = Status::InvalidArgument;
        return result;
    }
    const uintptr_t thread = callbacks.currentThread
        ? callbacks.currentThread(callbacks.context) : 0;
    RouteContext::SenderFrame *frame = RequestScope::topSender(context, thread);
    RequestScope *scope = frame ? frame->scope : nullptr;
    if (!scope || !scope->active_ || !frame->active || !frame->matchingSender ||
        thread != scope->thread_ ||
        invocation.callerReturnPC != scope->contract_.builderReturnPC) {
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = Status::NotMatched;
        return result;
    }

    // This is the first direct builder call in a sender that was itself
    // matched. A nested sender frame is intentionally unarmed and cannot
    // consume the outer sender's lease.
    if (!frame->armed) {
        if (frame->builderSeen) scope->markViolation();
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    result.matched = true;
    MacAddress address3 {};
    const bool exactShape = callbacksForBuilder(callbacks) &&
        invocation.driver == scope->driver_ &&
        invocation.driver == scope->contract_.driver &&
        invocation.wlc == scope->wlc_ && invocation.address3 &&
        invocation.subtype == DisassociateSubtype &&
        invocation.bodyLength == OriginalReasonBytes &&
        frame->leaseID == scope->leaseID_ && scope->leaseActive_;
    const bool ownerCurrent = exactShape &&
        callbacks.ownerGenerationCurrent(callbacks.context, scope->owner_,
                                         scope->requestID_,
                                         scope->ownerGeneration_);
    if (exactShape && !ownerCurrent) {
        scope->consumeLease(*frame);
        scope->markOwnerStale();
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    const bool exact = exactShape && ownerCurrent &&
        callbacks.readAddress3(callbacks.context, invocation.driver,
                               invocation.address3, &address3) &&
        sameAddress(address3, scope->bssid_);

    // A call from this exact native builder callsite with changed arguments
    // invalidates the lease. An unrelated builder with a different return PC
    // above leaves the outer lease untouched.
    scope->consumeLease(*frame);
    if (!exact) {
        scope->markViolation();
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    uint8_t ie[ReasonIEBytes] {};
    if (!encodeReasonIE(scope->extendedReason_, ie, sizeof(ie))) {
        scope->markViolation();
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    BuilderInvocation extended = invocation;
    extended.bodyLength = ExtendedBodyBytes;
    scope->phase_ = RequestScope::Phase::Building;
    scope->markStatus(Status::LeaseActive);
    void *packet = callbacks.originalBuilder(callbacks.context, extended);
    if (!packet) {
        scope->phase_ = RequestScope::Phase::Finished;
        scope->markStatus(Status::BuilderFailed);
        result.packet = nullptr;
        result.status = scope->status_;
        return result;
    }

    // Reentrant callbacks from the native builder can invalidate the token
    // after its lease was consumed. Before writing, recheck both request
    // generation and scope integrity. This packet is still unqueued and owned
    // here, so discard it and rebuild the original two-byte frame.
    const bool generationCurrent = callbacks.ownerGenerationCurrent(
        callbacks.context, scope->owner_, scope->requestID_,
        scope->ownerGeneration_);
    if (!generationCurrent && !scope->violated_)
        scope->markOwnerStale();
    if (scope->violated_ || scope->status_ == Status::OwnerStale) {
        callbacks.freeUnqueuedPacket(callbacks.context, invocation.driver,
                                     invocation.wlc, packet);
        scope->phase_ = RequestScope::Phase::Finished;
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = scope->status_;
        return result;
    }

    // bodyOutSlot is intentionally not read by this core. The adapter checks
    // the slot and writes atomically only after the successful packet return.
    if (!callbacks.writeBodyBytes(callbacks.context, invocation.driver,
                                  invocation.bodyOutSlot,
                                  ReasonIEAppendOffset, ie, sizeof(ie))) {
        callbacks.freeUnqueuedPacket(callbacks.context, invocation.driver,
                                     invocation.wlc, packet);
        scope->phase_ = RequestScope::Phase::Finished;
        scope->markStatus(Status::WriteFailed);
        // The extended packet is still unqueued. Discard it exactly once, then
        // rebuild the original two-byte frame so a failed optional IE write
        // does not suppress the native disassociation. Keep the result marked
        // WriteFailed even when this ordinary fallback builder succeeds.
        result.packet = callbacks.originalBuilder(callbacks.context, invocation);
        result.status = Status::WriteFailed;
        return result;
    }

    scope->phase_ = RequestScope::Phase::Finished;
    scope->markStatus(Status::Enhanced);
    frame->packetExtended = true;
    result.packet = packet;
    result.status = scope->status_;
    result.extended = true;
    return result;
}

} // namespace DisassociateFrame
} // namespace LegacyWiFi

#endif
