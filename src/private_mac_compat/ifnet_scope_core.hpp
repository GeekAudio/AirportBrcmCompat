// Offline-testable authorization core for nested ifnet ioctl scopes.
//
// The owner must serialize every Registry operation with one external lock and
// keep the Registry alive longer than every ticket. The core stores opaque
// scalar identities only: it never dereferences ifp, protocol, command, data,
// or thread. Callers must release the lock before invoking native code.
#ifndef PRIVATE_MAC_COMPAT_IFNET_SCOPE_CORE_HPP
#define PRIVATE_MAC_COMPAT_IFNET_SCOPE_CORE_HPP

#include <stddef.h>
#include <stdint.h>

namespace PrivateMAC { namespace IfnetScopeCore {

struct Tuple {
    uintptr_t ifp;
    uintptr_t protocol;
    uintptr_t command;
    uintptr_t data;

    constexpr Tuple(uintptr_t interfaceValue=0, uintptr_t protocolValue=0,
                    uintptr_t commandValue=0, uintptr_t dataValue=0)
        : ifp(interfaceValue), protocol(protocolValue), command(commandValue),
          data(dataValue) {}
};

enum class RootResult : uint8_t {
    Rejected,
    NoCallback,
    CallbackNoPerform,
    Performed
};

class Registry;

class RootTicket {
    friend class Registry;
    const Registry *issuer_;
    size_t slot_;
    uintptr_t owner_;
    uint64_t nonce_;
    RootTicket(const Registry *, size_t, uintptr_t, uint64_t);
    void clear();
public:
    RootTicket();
    ~RootTicket() = default;
    RootTicket(const RootTicket &) = delete;
    RootTicket &operator=(const RootTicket &) = delete;
    RootTicket(RootTicket &&) = delete;
    RootTicket &operator=(RootTicket &&) = delete;
    bool active() const { return issuer_ != nullptr; }
};

class CallbackTicket {
    friend class Registry;
    const Registry *issuer_;
    size_t slot_;
    uintptr_t owner_;
    uint64_t nonce_;
    CallbackTicket(const Registry *, size_t, uintptr_t, uint64_t);
    void clear();
public:
    CallbackTicket();
    ~CallbackTicket() = default;
    CallbackTicket(const CallbackTicket &) = delete;
    CallbackTicket &operator=(const CallbackTicket &) = delete;
    CallbackTicket(CallbackTicket &&) = delete;
    CallbackTicket &operator=(CallbackTicket &&) = delete;
    bool active() const { return issuer_ != nullptr; }
};

class PerformTicket {
    friend class Registry;
    const Registry *issuer_;
    size_t slot_;
    uintptr_t owner_;
    uint64_t nonce_;
    PerformTicket(const Registry *, size_t, uintptr_t, uint64_t);
    void clear();
public:
    PerformTicket();
    ~PerformTicket() = default;
    PerformTicket(const PerformTicket &) = delete;
    PerformTicket &operator=(const PerformTicket &) = delete;
    PerformTicket(PerformTicket &&) = delete;
    PerformTicket &operator=(PerformTicket &&) = delete;
    bool active() const { return issuer_ != nullptr; }
};

class Registry {
    friend class RootTicket;
    friend class CallbackTicket;
    friend class PerformTicket;

    static const size_t kCapacity = 64;
    struct Slot {
        bool occupied;
        bool valid;
        bool callbackStarted;
        bool callbackActive;
        bool performStarted;
        bool performActive;
        bool performCompleted;
        uintptr_t owner;
        uint64_t nonce;
        Tuple tuple;
        constexpr Slot()
            : occupied(false), valid(false), callbackStarted(false),
              callbackActive(false), performStarted(false),
              performActive(false), performCompleted(false), owner(0),
              nonce(0), tuple() {}
    };

    Slot slots_[kCapacity];
    uint64_t nonce_;
    bool poisoned_;

    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;
    Registry(Registry &&) = delete;
    Registry &operator=(Registry &&) = delete;

    static bool sameTuple(const Tuple &left, const Tuple &right) {
        return left.ifp == right.ifp && left.protocol == right.protocol &&
               left.command == right.command && left.data == right.data;
    }
    static void revoke(Slot &slot) { slot.valid = false; }
    size_t findOwner(uintptr_t owner) const {
        for (size_t i=0; i<kCapacity; ++i)
            if (slots_[i].occupied && slots_[i].owner == owner) return i;
        return kCapacity;
    }
    size_t findFree() const {
        for (size_t i=0; i<kCapacity; ++i)
            if (!slots_[i].occupied) return i;
        return kCapacity;
    }
    bool matches(const Registry *issuer, size_t index, uintptr_t owner,
                 uint64_t nonce) const {
        return issuer == this && index < kCapacity &&
               slots_[index].occupied && slots_[index].owner == owner &&
               slots_[index].nonce == nonce;
    }
    void release(size_t index) {
        if (index < kCapacity) slots_[index] = Slot();
    }
    bool nextNonce(uint64_t &out) {
        if (poisoned_) return false;
        if (nonce_ == UINT64_MAX) {
            poisoned_ = true;
            for (size_t i=0; i<kCapacity; ++i)
                if (slots_[i].occupied) revoke(slots_[i]);
            return false;
        }
        out = ++nonce_;
        return true;
    }

public:
    static const size_t Capacity = kCapacity;

    // initialNonce exists to make wrap behavior deterministically testable.
    // Production should use the default zero value and one long-lived registry.
    constexpr explicit Registry(uint64_t initialNonce=0)
        : slots_(), nonce_(initialNonce), poisoned_(false) {}

    bool beginRoot(uintptr_t thread, const Tuple &tuple, RootTicket &out) {
        if (thread == 0) return false;
        const size_t existing = findOwner(thread);
        if (existing != kCapacity) {
            // Any reentrant root attempt poisons the outer authorization until
            // its owner ends it, even when the caller reused a nonempty ticket.
            revoke(slots_[existing]);
            return false;
        }
        if (out.active() || poisoned_) return false;
        const size_t index = findFree();
        if (index == kCapacity) return false;
        uint64_t nonce=0;
        if (!nextNonce(nonce)) return false;
        Slot slot;
        slot.occupied = true;
        slot.valid = true;
        slot.owner = thread;
        slot.nonce = nonce;
        slot.tuple = tuple;
        slots_[index] = slot;
        out.issuer_ = this;
        out.slot_ = index;
        out.owner_ = thread;
        out.nonce_ = nonce;
        return true;
    }

    RootResult endRoot(uintptr_t thread, RootTicket &ticket) {
        if (!matches(ticket.issuer_, ticket.slot_, ticket.owner_, ticket.nonce_)) {
            if (ticket.issuer_ == this) ticket.clear();
            return RootResult::Rejected;
        }
        Slot &slot = slots_[ticket.slot_];
        if (thread != slot.owner) {
            revoke(slot);
            return RootResult::Rejected;
        }
        RootResult result = RootResult::Rejected;
        if (slot.valid && !slot.callbackActive && !slot.performActive) {
            if (!slot.callbackStarted) result = RootResult::NoCallback;
            else if (slot.performCompleted) result = RootResult::Performed;
            else result = RootResult::CallbackNoPerform;
        } else {
            revoke(slot);
        }
        const size_t index = ticket.slot_;
        ticket.clear();
        release(index);
        return result;
    }

    // This is called only by the fixed, admitted interface callback wrapper.
    bool beginCallback(const RootTicket &root, uintptr_t thread,
                       const Tuple &tuple, CallbackTicket &out) {
        if (!matches(root.issuer_, root.slot_, root.owner_, root.nonce_))
            return false;
        Slot &slot = slots_[root.slot_];
        if (thread != slot.owner || !slot.valid || out.active() ||
            !sameTuple(slot.tuple, tuple) || slot.callbackStarted) {
            revoke(slot);
            return false;
        }
        slot.callbackStarted = true;
        slot.callbackActive = true;
        out.issuer_ = this;
        out.slot_ = root.slot_;
        out.owner_ = root.owner_;
        out.nonce_ = root.nonce_;
        return true;
    }

    bool endCallback(uintptr_t thread, CallbackTicket &ticket) {
        if (!matches(ticket.issuer_, ticket.slot_, ticket.owner_, ticket.nonce_)) {
            if (ticket.issuer_ == this) ticket.clear();
            return false;
        }
        Slot &slot = slots_[ticket.slot_];
        if (thread != slot.owner) {
            revoke(slot);
            return false;
        }
        const bool accepted = slot.valid && slot.callbackActive &&
                             !slot.performActive;
        if (slot.performActive) revoke(slot);
        slot.callbackActive = false;
        ticket.clear();
        return accepted;
    }

    // The fixed callback must enter once, then the expected native perform
    // replacement may claim exactly one call with the identical argument tuple.
    bool claimPerform(const CallbackTicket &callback, uintptr_t thread,
                      const Tuple &tuple, PerformTicket &out) {
        if (!matches(callback.issuer_, callback.slot_, callback.owner_,
                     callback.nonce_)) return false;
        Slot &slot = slots_[callback.slot_];
        if (thread != slot.owner || !slot.valid || !slot.callbackActive ||
            out.active() || slot.performStarted ||
            !sameTuple(slot.tuple, tuple)) {
            revoke(slot);
            return false;
        }
        slot.performStarted = true;
        slot.performActive = true;
        out.issuer_ = this;
        out.slot_ = callback.slot_;
        out.owner_ = callback.owner_;
        out.nonce_ = callback.nonce_;
        return true;
    }

    bool held(const PerformTicket &ticket, uintptr_t thread,
              const Tuple &tuple) {
        if (!matches(ticket.issuer_, ticket.slot_, ticket.owner_, ticket.nonce_))
            return false;
        Slot &slot = slots_[ticket.slot_];
        const bool accepted = thread == slot.owner && slot.valid &&
                              slot.callbackActive && slot.performActive &&
                              sameTuple(slot.tuple, tuple);
        if (!accepted) revoke(slot);
        return accepted;
    }

    bool endPerform(uintptr_t thread, PerformTicket &ticket) {
        if (!matches(ticket.issuer_, ticket.slot_, ticket.owner_, ticket.nonce_)) {
            if (ticket.issuer_ == this) ticket.clear();
            return false;
        }
        Slot &slot = slots_[ticket.slot_];
        if (thread != slot.owner) {
            revoke(slot);
            return false;
        }
        const bool accepted = slot.valid && slot.callbackActive &&
                              slot.performActive;
        slot.performActive = false;
        slot.performCompleted = accepted;
        ticket.clear();
        return accepted;
    }
};

inline RootTicket::RootTicket()
    : issuer_(nullptr), slot_(static_cast<size_t>(-1)), owner_(0), nonce_(0) {}
inline RootTicket::RootTicket(const Registry *issuer, size_t slot,
                              uintptr_t owner, uint64_t nonce)
    : issuer_(issuer), slot_(slot), owner_(owner), nonce_(nonce) {}
inline void RootTicket::clear() {
    issuer_=nullptr; slot_=static_cast<size_t>(-1); owner_=0; nonce_=0;
}

inline CallbackTicket::CallbackTicket()
    : issuer_(nullptr), slot_(static_cast<size_t>(-1)), owner_(0), nonce_(0) {}
inline CallbackTicket::CallbackTicket(const Registry *issuer, size_t slot,
                                      uintptr_t owner, uint64_t nonce)
    : issuer_(issuer), slot_(slot), owner_(owner), nonce_(nonce) {}
inline void CallbackTicket::clear() {
    issuer_=nullptr; slot_=static_cast<size_t>(-1); owner_=0; nonce_=0;
}

inline PerformTicket::PerformTicket()
    : issuer_(nullptr), slot_(static_cast<size_t>(-1)), owner_(0), nonce_(0) {}
inline PerformTicket::PerformTicket(const Registry *issuer, size_t slot,
                                    uintptr_t owner, uint64_t nonce)
    : issuer_(issuer), slot_(slot), owner_(owner), nonce_(nonce) {}
inline void PerformTicket::clear() {
    issuer_=nullptr; slot_=static_cast<size_t>(-1); owner_=0; nonce_=0;
}

} } // namespace PrivateMAC::IfnetScopeCore

#endif
