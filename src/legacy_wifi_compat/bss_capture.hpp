// Owned snapshots that bridge the pinned 4331 receive-refresh parser to the
// later bodyless current-BSS record. This portable core never follows an
// opaque child pointer; the kernel adapter must serialize every Registry call
// with the same short lock used by DisassociateMemory::State.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_BSS_CAPTURE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_BSS_CAPTURE_HPP

#include "current_bss.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

namespace LegacyWiFi {
namespace BSSCapture {

namespace B = CurrentBSS;
namespace D = NetworkIdentity;
namespace N = NetworkMatch;
namespace A = NetworkAssurance;

constexpr size_t PendingCapacity = 8;
constexpr size_t RecordSize4331 = B::Record4331Size;
// NetworkIdentity consumes only ESS/IBSS mode and the privacy fallback bit.
// Short-slot and other Beacon capability flags are not network identity.
constexpr uint16_t IdentityCapabilityMask = 0x0013;

struct Fingerprint {
    uint8_t bssid[B::BSSIDSize] {};
    uint8_t ssidLength = 0;
    uint8_t ssid[N::MaximumSSIDLength] {};
    uint16_t capability = 0;
};

inline bool sameFingerprint(const Fingerprint &a, const Fingerprint &b) {
    return a.ssidLength <= N::MaximumSSIDLength &&
        b.ssidLength <= N::MaximumSSIDLength &&
        memcmp(a.bssid, b.bssid, B::BSSIDSize) == 0 &&
        a.ssidLength == b.ssidLength &&
        (!a.ssidLength || memcmp(a.ssid, b.ssid, a.ssidLength) == 0) &&
        a.capability == b.capability;
}

// Extract only fields that participate in the network identity. The capability
// key contains only ESS/IBSS and Privacy bits. DTIM at +0x60, channel, other
// capability bits, RSSI, scan metadata, body pointer and body length are
// excluded. `record` is an owned byte copy, not a native pointer to be followed
// here. On failure, `output` is unchanged.
inline bool fingerprint(const uint8_t *record, size_t recordSize,
                       Fingerprint *output) {
    if (!record || !output || recordSize != RecordSize4331) return false;
    Fingerprint value {};
    memcpy(value.bssid, record, sizeof(value.bssid));
    if (!B::validBSSID(value.bssid)) return false;
    value.ssidLength = record[B::SSIDLengthOffset];
    if (value.ssidLength > N::MaximumSSIDLength) return false;
    if (value.ssidLength)
        memcpy(value.ssid, record + B::SSIDOffset, value.ssidLength);
    value.capability = ScanBridge::read16(record + B::Capability4331Offset) &
        IdentityCapabilityMask;
    *output = value;
    return true;
}

inline bool bodyless4331(const uint8_t *record, size_t recordSize) {
    return record && recordSize == RecordSize4331 &&
        ScanBridge::read64(record + B::IEPointerOffset) == 0 &&
        ScanBridge::read16(record + B::IELengthOffset) == 0;
}

inline bool snapshotMatches(const Fingerprint &fp,
                            const B::OwnedSnapshot &snapshot) {
    static const uint16_t capabilityToAPMode[4] = {0, 2, 1, 3};
    return N::valid(snapshot.network) &&
        snapshot.network.fils == N::FILS::Absent &&
        snapshot.network.ssidLength == fp.ssidLength &&
        (!fp.ssidLength ||
         memcmp(snapshot.network.ssid, fp.ssid, fp.ssidLength) == 0) &&
        snapshot.network.apMode == capabilityToAPMode[fp.capability & 3] &&
        memcmp(snapshot.bssid, fp.bssid, B::BSSIDSize) == 0 &&
        static_cast<uint8_t>(snapshot.networkAssurance) <=
            static_cast<uint8_t>(A::State::Enabled);
}

// Decode the refresh parser's bodyless 4331 stack record with the full body
// copied from its raw Beacon/Probe Response input. The synthetic pointer value
// only satisfies CurrentBSS::decode's null/length consistency check; no code
// follows it. The original record/body are never modified. Unknown Network
// Assurance is preserved as a valid state alongside the decoded identity.
// Output remains unchanged on every failure.
inline int decodeProduced4331(const uint8_t *record, size_t recordSize,
                              const uint8_t *fullBody, size_t bodySize,
                              B::OwnedSnapshot *output) {
    if (!record || !output || recordSize != RecordSize4331) return EINVAL;
    if (bodySize > B::MaximumBeaconBodyBytes) return EOVERFLOW;
    if (!bodySize) return EOPNOTSUPP;
    if (bodySize < B::BeaconFixedBodyBytes) return EINVAL;
    if (!fullBody) return EINVAL;
    const uintptr_t bodyAddress = reinterpret_cast<uintptr_t>(fullBody);
    if (bodyAddress > UINTPTR_MAX - bodySize) return EINVAL;
    if (!bodyless4331(record, recordSize)) return EINVAL;

    Fingerprint fp {};
    if (!fingerprint(record, recordSize, &fp)) return EINVAL;
    // This is a producer-consistency check, not a fingerprint comparison:
    // require the complete raw capability word from the body to equal the
    // parser's complete word, including non-identity flags.
    if (ScanBridge::read16(record + B::Capability4331Offset) !=
        ScanBridge::read16(fullBody + 10)) return EINVAL;

    uint8_t recordWithBody[RecordSize4331] {};
    memcpy(recordWithBody, record, sizeof(recordWithBody));
    // Nonzero sentinel only: CurrentBSS::decode checks presence consistency
    // and consumes the separately supplied owned bytes, never this address.
    recordWithBody[B::IEPointerOffset] = 1;
    ScanBridge::write16(recordWithBody + B::IELengthOffset,
                        static_cast<uint16_t>(bodySize));

    B::OwnedSnapshot decoded {};
    const int error = B::decode(D::Source::Pinned4331, recordWithBody,
                                sizeof(recordWithBody), fullBody, bodySize,
                                &decoded);
    memset(recordWithBody, 0, sizeof(recordWithBody));
    if (error) {
        memset(&decoded, 0, sizeof(decoded));
        return error;
    }
    if (!snapshotMatches(fp, decoded)) {
        memset(&decoded, 0, sizeof(decoded));
        return EINVAL;
    }
    *output = decoded;
    memset(&decoded, 0, sizeof(decoded));
    return 0;
}

class Registry;

class Ticket {
public:
    Ticket() = default;
    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;
    Ticket(Ticket &&) = delete;
    Ticket &operator=(Ticket &&) = delete;

private:
    friend class Registry;
    const Registry *owner_ = nullptr;
    uintptr_t thread_ = 0;
    uint64_t nonce_ = 0;
};

class Registry {
public:
    Registry() = default;
    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;
    Registry(Registry &&) = delete;
    Registry &operator=(Registry &&) = delete;

    // Reserve a new one-shot parser transaction. The same thread's prior
    // pending transaction is invalidated first. A full table rejects the new
    // reservation without evicting other threads or poisoning later attempts.
    // Nonce exhaustion permanently disables pending captures; values never
    // wrap or get reused. The registry must outlive every ticket it issues.
    bool begin(uintptr_t thread, Ticket &ticket) {
        if (!thread || !ticketAvailable(ticket) || noncePoisoned_) return false;
        clearThread(thread);
        if (!nextNonce_) {
            noncePoisoned_ = true;
            clearPending();
            return false;
        }
        size_t slot = PendingCapacity;
        for (size_t i = 0; i < PendingCapacity; ++i) {
            if (!pending_[i].used) { slot = i; break; }
        }
        if (slot == PendingCapacity) return false;

        Pending value {};
        value.used = true;
        value.thread = thread;
        value.nonce = nextNonce_;
        pending_[slot] = value;
        ticket.owner_ = this;
        ticket.thread_ = thread;
        ticket.nonce_ = nextNonce_;
        nextNonce_ = nextNonce_ == UINT64_MAX ? 0 : nextNonce_ + 1;
        return true;
    }

    void invalidate(uintptr_t thread) {
        if (thread) clearThread(thread);
    }

    // Cancel only the exact reservation/staged entry represented by this
    // ticket. A stale outer ticket cannot clear a newer nested token from the
    // same thread, and committed state is intentionally unaffected.
    void cancel(const Ticket &ticket) {
        Pending *slot = findTicket(ticket);
        if (slot) clear(*slot);
    }

    void clearPending() {
        for (size_t i = 0; i < PendingCapacity; ++i) clear(pending_[i]);
    }

    bool stage(const Ticket &ticket, uint64_t epoch, uintptr_t wlc,
               uintptr_t cfg, uintptr_t source,
               const uint8_t *record, size_t recordSize,
               const B::OwnedSnapshot &snapshot) {
        Pending *slot = findTicket(ticket);
        if (!slot || slot->staged) return false;
        Fingerprint fp {};
        const bool valid = epoch && wlc && cfg && source && record &&
            recordSize == RecordSize4331 && bodyless4331(record, recordSize) &&
            fingerprint(record, recordSize, &fp) && snapshotMatches(fp, snapshot);
        if (!valid) {
            clear(*slot);
            return false;
        }
        slot->epoch = epoch;
        slot->wlc = wlc;
        slot->cfg = cfg;
        slot->source = source;
        slot->fingerprint = fp;
        slot->snapshot = snapshot;
        slot->staged = true;
        return true;
    }

    // Consume the staged entry belonging to `thread` before validating any
    // supplied key. Even a mismatched BSSinit attempt cannot leave a stale
    // token for later stack-address reuse. Output stays unchanged on failure.
    bool take(uintptr_t thread, uint64_t epochBefore, uintptr_t wlc,
              uintptr_t cfg, uintptr_t source,
              const uint8_t *record, size_t recordSize,
              B::OwnedSnapshot *output) {
        if (!thread) return false;
        Pending consumed {};
        bool found = false;
        for (size_t i = 0; i < PendingCapacity; ++i) {
            if (pending_[i].used && pending_[i].thread == thread) {
                consumed = pending_[i];
                clear(pending_[i]);
                found = true;
                break;
            }
        }
        if (!found) return false;

        Fingerprint fp {};
        const bool valid = output && consumed.staged && epochBefore &&
            consumed.epoch == epochBefore && consumed.wlc == wlc &&
            consumed.cfg == cfg && consumed.source == source &&
            bodyless4331(record, recordSize) &&
            fingerprint(record, recordSize, &fp) &&
            sameFingerprint(consumed.fingerprint, fp) &&
            snapshotMatches(fp, consumed.snapshot);
        if (valid) *output = consumed.snapshot;
        memset(&consumed, 0, sizeof(consumed));
        return valid;
    }

    // Publish only a bodyless 4331 current record whose identity fields agree
    // with the owned snapshot. `target` and other addresses are comparison
    // keys; this core never dereferences them.
    bool publish(uint64_t epoch, uintptr_t wlc, uintptr_t cfg,
                 uintptr_t target, const uint8_t *record, size_t recordSize,
                 const B::OwnedSnapshot &snapshot) {
        Fingerprint fp {};
        if (!epoch || !wlc || !cfg || !target ||
            !bodyless4331(record, recordSize) ||
            !fingerprint(record, recordSize, &fp) ||
            !snapshotMatches(fp, snapshot)) return false;
        Committed value {};
        value.valid = true;
        value.epoch = epoch;
        value.wlc = wlc;
        value.cfg = cfg;
        value.target = target;
        value.fingerprint = fp;
        value.snapshot = snapshot;
        committed_ = value;
        return true;
    }

    // A retained snapshot is usable only for the same epoch and opaque owner
    // keys, with a matching identity fingerprint and an actually bodyless
    // current record. Output remains unchanged on every failure.
    bool lookup(uint64_t epoch, uintptr_t wlc, uintptr_t cfg,
                uintptr_t target, const uint8_t *record, size_t recordSize,
                B::OwnedSnapshot *output) const {
        if (!output || !committed_.valid || !epoch || !wlc || !cfg || !target ||
            committed_.epoch != epoch || committed_.wlc != wlc ||
            committed_.cfg != cfg || committed_.target != target ||
            !bodyless4331(record, recordSize)) return false;
        Fingerprint fp {};
        if (!fingerprint(record, recordSize, &fp) ||
            !sameFingerprint(committed_.fingerprint, fp) ||
            !snapshotMatches(fp, committed_.snapshot)) return false;
        *output = committed_.snapshot;
        return true;
    }

private:
    struct Pending {
        bool used = false;
        bool staged = false;
        uintptr_t thread = 0;
        uint64_t nonce = 0;
        uint64_t epoch = 0;
        uintptr_t wlc = 0, cfg = 0, source = 0;
        Fingerprint fingerprint {};
        B::OwnedSnapshot snapshot {};
    };

    struct Committed {
        bool valid = false;
        uint64_t epoch = 0;
        uintptr_t wlc = 0, cfg = 0, target = 0;
        Fingerprint fingerprint {};
        B::OwnedSnapshot snapshot {};
    };

    static bool ticketAvailable(const Ticket &ticket) {
        return !ticket.owner_ && !ticket.thread_ && !ticket.nonce_;
    }

    Pending *findTicket(const Ticket &ticket) {
        if (ticket.owner_ != this || !ticket.thread_ || !ticket.nonce_) return nullptr;
        for (size_t i = 0; i < PendingCapacity; ++i) {
            Pending &slot = pending_[i];
            if (slot.used && slot.thread == ticket.thread_ &&
                slot.nonce == ticket.nonce_) return &slot;
        }
        return nullptr;
    }

    void clearThread(uintptr_t thread) {
        for (size_t i = 0; i < PendingCapacity; ++i)
            if (pending_[i].used && pending_[i].thread == thread)
                clear(pending_[i]);
    }

    static void clear(Pending &pending) {
        pending = Pending {};
    }

    friend struct TestAccess;
    Pending pending_[PendingCapacity] {};
    Committed committed_ {};
    uint64_t nextNonce_ = 1;
    bool noncePoisoned_ = false;
};

} // namespace BSSCapture
} // namespace LegacyWiFi

#endif
