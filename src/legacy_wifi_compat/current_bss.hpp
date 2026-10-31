// Owned snapshot and one-shot local-disconnect completion core for the two
// pinned El Capitan Broadcom children. This file never dereferences a child
// IE pointer or invokes a private worker.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_CURRENT_BSS_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_CURRENT_BSS_HPP

#include "network_identity.hpp"
#include "network_assurance.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

namespace LegacyWiFi {
namespace CurrentBSS {

constexpr size_t BSSIDSize = 6;
constexpr size_t Record4331Size = 0xa0;
constexpr size_t Record43224Size = 0x98;
constexpr size_t SSIDLengthOffset = 0x08;
constexpr size_t SSIDOffset = 0x09;
// These child fields hold bcn_prb: the complete Beacon/Probe Response body,
// including timestamp (8), interval (2), capability (2), then the IE list.
// They are not the provider's already-normalized scan-result IE fields.
constexpr size_t IEPointerOffset = 0x68;
constexpr size_t IELengthOffset = 0x70;
constexpr size_t BeaconFixedBodyBytes = 12;
constexpr size_t MaximumBeaconBodyBytes = BeaconFixedBodyBytes + ScanBridge::MaximumIEBytes;
constexpr size_t Capability4331Offset = 0x62;
constexpr size_t Capability43224Offset = 0x5e;

struct OwnedSnapshot {
    uint8_t bssid[BSSIDSize] {};
    NetworkMatch::Identity network {};
    // State observed in the owned IE bytes of this legacy current-BSS record.
    // It is not proof that the record contains the latest beacon received over
    // the air or that a native sibling's cached Beacon has the same state.
    NetworkAssurance::State networkAssurance = NetworkAssurance::State::Unknown;
};

inline bool validBSSID(const uint8_t bssid[BSSIDSize]) {
    if (!bssid || (bssid[0] & 1U)) return false;
    uint8_t aggregate = 0;
    for (size_t i = 0; i < BSSIDSize; ++i) aggregate |= bssid[i];
    return aggregate != 0;
}

inline bool sourceLayout(NetworkIdentity::Source source, size_t *recordSize,
                         size_t *capabilityOffset) {
    if (!recordSize || !capabilityOffset) return false;
    switch (source) {
    case NetworkIdentity::Source::Pinned4331:
        *recordSize = Record4331Size;
        *capabilityOffset = Capability4331Offset;
        return true;
    case NetworkIdentity::Source::Pinned43224:
        *recordSize = Record43224Size;
        *capabilityOffset = Capability43224Offset;
        return true;
    default:
        return false;
    }
}

// `record` and `copiedBody` must already be owned synchronous copies made by
// the kernel adapter while holding the controller gate. The inline pointer
// is checked only for null/non-null consistency with the declared length; it
// is never followed here. Only the tail after the fixed 12-byte body is an IE
// list. A missing body is unknown, not an empty IE list: receive refresh can
// clear the stored body while the connection still uses RSN/WPA. On failure,
// `output` is unchanged.
inline int decode(NetworkIdentity::Source source,
                  const uint8_t *record, size_t recordSize,
                  const uint8_t *copiedBody, size_t copiedBodySize,
                  OwnedSnapshot *output) {
    size_t expectedRecordSize = 0;
    size_t capabilityOffset = 0;
    if (!sourceLayout(source, &expectedRecordSize, &capabilityOffset))
        return EOPNOTSUPP;
    if (!record || !output || recordSize != expectedRecordSize) return EINVAL;

    uint8_t bssid[BSSIDSize] {};
    memcpy(bssid, record, sizeof(bssid));
    if (!validBSSID(bssid)) return EINVAL;

    const size_t ssidLength = record[SSIDLengthOffset];
    if (ssidLength > NetworkMatch::MaximumSSIDLength) return EINVAL;

    const uint64_t inlineIEPointer = ScanBridge::read64(record + IEPointerOffset);
    const size_t declaredBodySize = ScanBridge::read16(record + IELengthOffset);
    if (declaredBodySize > MaximumBeaconBodyBytes) return EOVERFLOW;
    if ((inlineIEPointer != 0) != (declaredBodySize != 0) ||
        copiedBodySize != declaredBodySize || (declaredBodySize && !copiedBody))
        return EINVAL;
    if (!declaredBodySize) return EOPNOTSUPP;
    if (declaredBodySize < BeaconFixedBodyBytes) return EINVAL;
    const size_t ieSize = declaredBodySize - BeaconFixedBodyBytes;

    uint8_t normalized[ScanBridge::FixedLegacyResultSize] {};
    normalized[0] = 1; // The fixed identity decoder's audited schema version.
    ScanBridge::write16(normalized + NetworkIdentity::CapabilityOffset,
                        ScanBridge::read16(record + capabilityOffset));
    normalized[NetworkIdentity::SSIDLengthOffset] =
        static_cast<uint8_t>(ssidLength);
    if (ssidLength)
        memcpy(normalized + NetworkIdentity::SSIDOffset,
               record + SSIDOffset, ssidLength);
    ScanBridge::write16(normalized + ScanBridge::IELengthOffset,
                        static_cast<uint16_t>(ieSize));
    if (ieSize)
        memcpy(normalized + ScanCompat::IEOffset,
               copiedBody + BeaconFixedBodyBytes, ieSize);

    NetworkMatch::Identity identity {};
    const int error = NetworkIdentity::decode(source, normalized,
        sizeof(normalized), &identity);
    memset(normalized, 0, sizeof(normalized));
    if (error) return error;

    NetworkAssurance::State assurance = NetworkAssurance::State::Unknown;
    const int assuranceError = NetworkAssurance::parse(
        copiedBody + BeaconFixedBodyBytes, ieSize, &assurance);
    if (assuranceError) {
        memset(&identity, 0, sizeof(identity));
        return assuranceError;
    }

    OwnedSnapshot snapshot {};
    memcpy(snapshot.bssid, bssid, sizeof(snapshot.bssid));
    snapshot.network = identity;
    snapshot.networkAssurance = assurance;
    *output = snapshot;
    memset(&identity, 0, sizeof(identity));
    return 0;
}

// The binding contains opaque identities supplied by the gated adapter. They
// are compared as values only and are never dereferenced by this core.
struct Binding {
    NetworkIdentity::Source source = NetworkIdentity::Source::Unknown;
    // The adapter must assign a monotonically increasing, non-reused generation
    // per owner operation. Never wrap/reuse it while a stale ticket may exist.
    uint64_t owner = 0;
    uint64_t generation = 0;
    uint64_t thread = 0;
    uint64_t driver = 0;
    uint64_t wlc = 0;
    uint64_t cfg = 0;
    uint8_t bssid[BSSIDSize] {};
};

struct WorkerEntry {
    Binding binding {};
    uint64_t returnPCOffset = 0;
    uint64_t arg0 = 0;
    uint64_t arg1 = 0;
    uint64_t arg2 = 0;
    uint64_t arg3 = 0;
    uint8_t liveBSSID[BSSIDSize] {};
};

struct WorkerExit {
    Binding binding {};
    int32_t status = -1;
    uint8_t liveBSSID[BSSIDSize] {};
    uint64_t currentIEPointer = 0;
    uint16_t currentIELength = 0;
};

class CompletionToken;

struct WorkerTicket {
    // Tickets are bound to the live stack token that issued them. The numeric
    // value is only a one-shot sequence within that token; it is not globally
    // unique and must never authorize a different token. Keep the ticket within
    // the same synchronous stack scope as its owner token.
    const CompletionToken *token = nullptr;
    uint64_t bindingOwner = 0;
    uint64_t bindingGeneration = 0;
    uint64_t value = 0;
};

constexpr uint64_t WorkerCallSite4331 = 0x5e1ee;
constexpr uint64_t WorkerCallSite43224 = 0x901e7;

inline bool sameBinding(const Binding &a, const Binding &b) {
    return a.source == b.source && a.owner == b.owner &&
        a.generation == b.generation && a.thread == b.thread &&
        a.driver == b.driver && a.wlc == b.wlc && a.cfg == b.cfg &&
        memcmp(a.bssid, b.bssid, BSSIDSize) == 0;
}

inline bool validBinding(const Binding &binding) {
    return (binding.source == NetworkIdentity::Source::Pinned4331 ||
            binding.source == NetworkIdentity::Source::Pinned43224) &&
        binding.owner != 0 && binding.generation != 0 && binding.thread != 0 &&
        binding.driver != 0 && binding.wlc != 0 && binding.cfg != 0 &&
        validBSSID(binding.bssid);
}

inline bool allZeroBSSID(const uint8_t bssid[BSSIDSize]) {
    if (!bssid) return false;
    uint8_t aggregate = 0;
    for (size_t i = 0; i < BSSIDSize; ++i) aggregate |= bssid[i];
    return aggregate == 0;
}

// Stack-scoped, fail-closed observation of the existing SET22 worker route.
// The adapter must always let the original provider/child path run; this type
// only validates entry and return evidence around that normal call.
class CompletionToken {
public:
    CompletionToken() = default;
    CompletionToken(const CompletionToken &) = delete;
    CompletionToken &operator=(const CompletionToken &) = delete;
    CompletionToken(CompletionToken &&) = delete;
    CompletionToken &operator=(CompletionToken &&) = delete;

    bool arm(const Binding &binding) {
        if (state != State::Empty || !validBinding(binding)) {
            state = State::Failed;
            return false;
        }
        bound = binding;
        state = State::Armed;
        return true;
    }

    bool workerEnter(const WorkerEntry &entry, WorkerTicket *ticket) {
        if (state != State::Armed || !ticket) {
            state = State::Failed;
            return false;
        }
        const bool is4331 = bound.source == NetworkIdentity::Source::Pinned4331;
        const uint64_t expectedPC = is4331 ? WorkerCallSite4331 : WorkerCallSite43224;
        const uint64_t expectedArg0 = is4331 ? bound.cfg : bound.wlc;
        if (!sameBinding(bound, entry.binding) ||
            entry.returnPCOffset != expectedPC || entry.arg0 != expectedArg0 ||
            entry.arg1 != 1 || entry.arg2 != 0 || entry.arg3 != 0 ||
            memcmp(entry.liveBSSID, bound.bssid, BSSIDSize) != 0 ||
            !validBSSID(entry.liveBSSID)) {
            state = State::Failed;
            return false;
        }
        // A token represents exactly one observed synchronous worker call.
        // Any second/nested call reaches this method in a non-Armed state and
        // permanently invalidates the token.
        activeTicket = 1;
        ticket->token = this;
        ticket->bindingOwner = bound.owner;
        ticket->bindingGeneration = bound.generation;
        ticket->value = activeTicket;
        state = State::InWorker;
        return true;
    }

    bool workerReturn(const WorkerTicket &ticket, const WorkerExit &exit) {
        if (state != State::InWorker || ticket.token != this ||
            ticket.bindingOwner != bound.owner ||
            ticket.bindingGeneration != bound.generation ||
            ticket.value == 0 ||
            ticket.value != activeTicket) {
            state = State::Failed;
            return false;
        }
        const bool cleared = allZeroBSSID(exit.liveBSSID);
        const bool childClean = bound.source != NetworkIdentity::Source::Pinned43224 ||
            (exit.currentIEPointer == 0 && exit.currentIELength == 0);
        if (!sameBinding(bound, exit.binding) || exit.status != 0 ||
            !cleared || !childClean) {
            state = State::Failed;
            return false;
        }
        state = State::Complete;
        return true;
    }

    // Called only after the ordinary outer SET22 handler has returned, still
    // under the same controller gate. A skipped/no-op worker cannot complete.
    bool consumeCompleted(const Binding &outerBinding) {
        if (state != State::Complete || !sameBinding(bound, outerBinding)) {
            state = State::Failed;
            return false;
        }
        state = State::Consumed;
        return true;
    }

    bool failed() const { return state == State::Failed; }

private:
    enum class State : uint8_t { Empty, Armed, InWorker, Complete, Consumed, Failed };

    State state = State::Empty;
    Binding bound {};
    uint64_t activeTicket = 0;
};

} // namespace CurrentBSS
} // namespace LegacyWiFi

#endif
