// Bounded, two-phase core for pruning manager-owned scan-cache references.
// This header knows nothing about the private provider node layout. Adapters
// supply checked readers and non-failing field writers for a pinned provider.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SELECTIVE_CACHE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SELECTIVE_CACHE_HPP

#include "network_match.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

namespace LegacyWiFi {
namespace SelectiveCache {

using Node = void *;
using LinkSlot = void *;

enum class Status : uint8_t {
    Ok,
    InvalidArgument,
    CapacityExceeded,
    NodeLimitExceeded,
    CorruptList,
    InvalidIdentity,
    IdentityUnavailable,
    AccessFailure,
    PlanNotReady,
    PlanConsumed,
    Stale
};

// Snapshot is an owned copy of the fields the core needs. `nextSlot` is an
// opaque address/token for the node's next pointer field; `previousLink` is
// the opaque address/token stored in the node's intrusive back-link field.
// `inspect` must validate readability before touching `node` and must not
// mutate provider state or re-enter this operation.
struct Snapshot {
    Node node = nullptr;
    LinkSlot nextSlot = nullptr;
    LinkSlot previousLink = nullptr;
    uint32_t referenceCount = 0;
    NetworkMatch::Identity identity {};
};

// readLink is read-only. The remaining callbacks are used only after every
// list item has been preflighted and revalidated. Commit callbacks must not
// fail or re-enter this API. Each writer may update only the designated field;
// writers and destroy must not touch request/aggregate lists, other nodes, or
// the caller's plan. destroy may release only the specified node and its
// owned IE allocation.
struct Accessors {
    void *context = nullptr;
    Status (*readLink)(void *context, LinkSlot slot, Node *value) = nullptr;
    Status (*inspect)(void *context, Node node, Snapshot *snapshot) = nullptr;
    void (*writeLink)(void *context, LinkSlot slot, Node value) = nullptr;
    void (*writePreviousLink)(void *context, Node node, LinkSlot value) = nullptr;
    void (*writeReferenceCount)(void *context, Node node, uint32_t value) = nullptr;
    void (*destroy)(void *context, Node node) = nullptr;
};

struct Entry {
    Snapshot snapshot {};
    Node savedNext = nullptr;
    Node finalNext = nullptr;
    LinkSlot finalPreviousLink = nullptr;
    bool matches = false;
};

struct Result {
    size_t examinedNodes = 0;
    size_t matchedNodes = 0;
    size_t retainedForRequests = 0;
    size_t destroyedNodes = 0;
};

struct Plan;
inline Status preflight(LinkSlot headSlot,
                        const NetworkMatch::Identity *key,
                        Entry *scratch,
                        size_t scratchCapacity,
                        size_t maxNodes,
                        const Accessors &accessors,
                        Plan *plan);
inline Status commit(Plan *plan, Result *result);
inline void resetPlan(Plan *plan, Entry *entries, size_t capacity);

// A Plan is intentionally opaque and non-copyable: copying or editing a ready
// plan could permit a second manager-reference drop or alter the preflight
// decision. Its caller-owned scratch storage must remain valid and unchanged
// until commit returns. The first commit attempt consumes the plan.
struct Plan {
    Plan() = default;
    Plan(const Plan &) = delete;
    Plan &operator=(const Plan &) = delete;

    size_t nodeCount() const { return count; }
    size_t matchingNodeCount() const { return matchCount; }

private:
    friend Status preflight(LinkSlot headSlot,
                            const NetworkMatch::Identity *key,
                            Entry *scratch,
                            size_t scratchCapacity,
                            size_t maxNodes,
                            const Accessors &accessors,
                            Plan *plan);
    friend Status commit(Plan *plan, Result *result);
    friend void resetPlan(Plan *plan, Entry *entries, size_t capacity);

    Entry *entries = nullptr;
    size_t capacity = 0;
    size_t count = 0;
    size_t matchCount = 0;
    LinkSlot headSlot = nullptr;
    Node originalHead = nullptr;
    Node finalHead = nullptr;
    NetworkMatch::Identity key {};
    Accessors accessors {};
    bool ready = false;
    bool consumed = false;
};

inline bool accessorsValid(const Accessors &accessors) {
    return accessors.readLink && accessors.inspect && accessors.writeLink &&
        accessors.writePreviousLink && accessors.writeReferenceCount &&
        accessors.destroy;
}

inline bool sameIdentity(const NetworkMatch::Identity &left,
                         const NetworkMatch::Identity &right) {
    if (!NetworkMatch::valid(left) || !NetworkMatch::valid(right)) return false;
    if (left.ssidLength != right.ssidLength ||
        left.encryptionModes != right.encryptionModes ||
        left.apMode != right.apMode || left.fils != right.fils) return false;
    return memcmp(left.ssid, right.ssid, left.ssidLength) == 0;
}

inline Status networkMatchStatus(int error) {
    if (error == 0) return Status::Ok;
    if (error == EOPNOTSUPP) return Status::IdentityUnavailable;
    return Status::InvalidIdentity;
}

inline void resetPlan(Plan *plan, Entry *entries, size_t capacity) {
    plan->entries = entries;
    plan->capacity = capacity;
    plan->count = 0;
    plan->matchCount = 0;
    plan->headSlot = nullptr;
    plan->originalHead = nullptr;
    plan->finalHead = nullptr;
    plan->key = NetworkMatch::Identity {};
    plan->accessors = Accessors {};
    plan->ready = false;
    plan->consumed = false;
}

// Phase one is read-only with respect to the provider list. The caller must
// hold the same serialization mechanism continuously through commit. It
// verifies the entire reachable list, including the intrusive back-link,
// every next slot, a manager-owned reference, and a fully classifiable
// candidate identity. No production field is written if validation fails.
inline Status preflight(LinkSlot headSlot,
                        const NetworkMatch::Identity *key,
                        Entry *scratch,
                        size_t scratchCapacity,
                        size_t maxNodes,
                        const Accessors &accessors,
                        Plan *plan) {
    if (!plan) return Status::InvalidArgument;
    resetPlan(plan, scratch, scratchCapacity);
    if (!headSlot || !key || !accessorsValid(accessors) ||
        (scratchCapacity != 0 && !scratch) || !NetworkMatch::valid(*key)) {
        return Status::InvalidArgument;
    }

    plan->headSlot = headSlot;
    plan->key = *key;
    plan->accessors = accessors;

    Node current = nullptr;
    if (accessors.readLink(accessors.context, headSlot, &current) != Status::Ok) {
        resetPlan(plan, scratch, scratchCapacity);
        return Status::AccessFailure;
    }
    plan->originalHead = current;
    LinkSlot expectedPreviousLink = headSlot;

    while (current) {
        if (plan->count >= maxNodes) {
            resetPlan(plan, scratch, scratchCapacity);
            return Status::NodeLimitExceeded;
        }
        if (plan->count >= scratchCapacity) {
            resetPlan(plan, scratch, scratchCapacity);
            return Status::CapacityExceeded;
        }

        for (size_t i = 0; i < plan->count; ++i) {
            if (plan->entries[i].snapshot.node == current) {
                resetPlan(plan, scratch, scratchCapacity);
                return Status::CorruptList;
            }
        }

        Snapshot snapshot {};
        if (accessors.inspect(accessors.context, current, &snapshot) != Status::Ok) {
            resetPlan(plan, scratch, scratchCapacity);
            return Status::AccessFailure;
        }
        if (snapshot.node != current || !snapshot.nextSlot ||
            snapshot.previousLink != expectedPreviousLink ||
            snapshot.referenceCount == 0 || snapshot.nextSlot == headSlot) {
            resetPlan(plan, scratch, scratchCapacity);
            return Status::CorruptList;
        }
        for (size_t i = 0; i < plan->count; ++i) {
            if (plan->entries[i].snapshot.nextSlot == snapshot.nextSlot) {
                resetPlan(plan, scratch, scratchCapacity);
                return Status::CorruptList;
            }
        }

        Node next = nullptr;
        if (accessors.readLink(accessors.context, snapshot.nextSlot, &next) != Status::Ok) {
            resetPlan(plan, scratch, scratchCapacity);
            return Status::AccessFailure;
        }

        bool matches = false;
        const int matchError = NetworkMatch::matches(&snapshot.identity, &plan->key,
                                                      &matches);
        const Status matchStatus = networkMatchStatus(matchError);
        if (matchStatus != Status::Ok) {
            resetPlan(plan, scratch, scratchCapacity);
            return matchStatus;
        }

        Entry &entry = plan->entries[plan->count++];
        entry.snapshot = snapshot;
        entry.savedNext = next;
        entry.finalNext = nullptr;
        entry.finalPreviousLink = nullptr;
        entry.matches = matches;
        if (matches) ++plan->matchCount;

        current = next;
        expectedPreviousLink = snapshot.nextSlot;
    }

    // Precompute the complete survivor chain. Commit will never discover or
    // follow a node after it starts changing production links.
    Node nextSurvivor = nullptr;
    for (size_t i = plan->count; i > 0; --i) {
        Entry &entry = plan->entries[i - 1];
        if (!entry.matches) {
            entry.finalNext = nextSurvivor;
            nextSurvivor = entry.snapshot.node;
        }
    }
    plan->finalHead = nextSurvivor;

    LinkSlot previousSurvivorLink = headSlot;
    for (size_t i = 0; i < plan->count; ++i) {
        Entry &entry = plan->entries[i];
        if (!entry.matches) {
            entry.finalPreviousLink = previousSurvivorLink;
            previousSurvivorLink = entry.snapshot.nextSlot;
        }
    }

    plan->ready = true;
    return Status::Ok;
}

// Phase two consumes the plan on its first attempt and first revalidates every
// captured field, before performing any production write. This detects a plan
// used after an accidental gate release; it does not replace holding the same
// serialization mechanism continuously from preflight through commit. Once
// revalidation succeeds, the only node walks are through the bounded plan.
inline Status commit(Plan *plan, Result *result) {
    if (!plan || !result) return Status::InvalidArgument;
    if (plan->consumed) return Status::PlanConsumed;
    if (!plan->ready || !accessorsValid(plan->accessors) ||
        (plan->count != 0 && !plan->entries)) return Status::PlanNotReady;

    plan->consumed = true;
    const Accessors &accessors = plan->accessors;

    Node currentHead = nullptr;
    if (accessors.readLink(accessors.context, plan->headSlot, &currentHead) != Status::Ok ||
        currentHead != plan->originalHead) return Status::Stale;

    Node expectedNode = currentHead;
    LinkSlot expectedPrevious = plan->headSlot;
    size_t checkedMatches = 0;
    for (size_t i = 0; i < plan->count; ++i) {
        const Entry &entry = plan->entries[i];
        if (!expectedNode || entry.snapshot.node != expectedNode ||
            entry.snapshot.previousLink != expectedPrevious) return Status::Stale;
        Snapshot current {};
        if (accessors.inspect(accessors.context, entry.snapshot.node, &current) != Status::Ok ||
            current.node != entry.snapshot.node ||
            current.nextSlot != entry.snapshot.nextSlot ||
            current.previousLink != entry.snapshot.previousLink ||
            current.referenceCount != entry.snapshot.referenceCount ||
            !sameIdentity(current.identity, entry.snapshot.identity)) return Status::Stale;

        Node currentNext = nullptr;
        if (accessors.readLink(accessors.context, current.nextSlot, &currentNext) != Status::Ok ||
            currentNext != entry.savedNext) return Status::Stale;
        bool matches = false;
        if (NetworkMatch::matches(&current.identity, &plan->key, &matches) ||
            matches != entry.matches) return Status::Stale;
        if (matches) ++checkedMatches;
        expectedNode = currentNext;
        expectedPrevious = current.nextSlot;
    }
    if (expectedNode || checkedMatches != plan->matchCount) return Status::Stale;

    // Caller-owned scratch is required to remain unchanged, but do not trust
    // its cached decisions or derived topology merely because live snapshots
    // still match. Recompute those values before the first provider write.
    Node nextSurvivor = nullptr;
    for (size_t i = plan->count; i > 0; --i) {
        const Entry &entry = plan->entries[i - 1];
        if (entry.matches) {
            if (entry.finalNext || entry.finalPreviousLink) return Status::Stale;
        } else {
            if (entry.finalNext != nextSurvivor) return Status::Stale;
            nextSurvivor = entry.snapshot.node;
        }
    }
    if (nextSurvivor != plan->finalHead) return Status::Stale;
    LinkSlot previousSurvivor = plan->headSlot;
    for (size_t i = 0; i < plan->count; ++i) {
        const Entry &entry = plan->entries[i];
        if (!entry.matches) {
            if (entry.finalPreviousLink != previousSurvivor) return Status::Stale;
            previousSurvivor = entry.snapshot.nextSlot;
        }
    }

    Result completed {};
    completed.examinedNodes = plan->count;
    completed.matchedNodes = plan->matchCount;
    if (plan->matchCount == 0) {
        *result = completed;
        return Status::Ok;
    }

    // Rewrite only the manager list. A referenced request result remains owned
    // by its request wrapper; its node's detached intrusive links are cleared
    // so they cannot retain pointers into a later-mutated manager list.
    for (size_t i = 0; i < plan->count; ++i) {
        const Entry &entry = plan->entries[i];
        if (entry.matches) {
            accessors.writeLink(accessors.context, entry.snapshot.nextSlot, nullptr);
            accessors.writePreviousLink(accessors.context, entry.snapshot.node, nullptr);
        } else {
            accessors.writeLink(accessors.context, entry.snapshot.nextSlot, entry.finalNext);
            accessors.writePreviousLink(accessors.context, entry.snapshot.node,
                                        entry.finalPreviousLink);
        }
    }
    accessors.writeLink(accessors.context, plan->headSlot, plan->finalHead);

    for (size_t i = 0; i < plan->count; ++i) {
        const Entry &entry = plan->entries[i];
        if (!entry.matches) continue;
        const uint32_t remaining = entry.snapshot.referenceCount - 1;
        accessors.writeReferenceCount(accessors.context, entry.snapshot.node, remaining);
        if (remaining != 0) ++completed.retainedForRequests;
    }

    // All list and reference writes finish before any destructor runs. The
    // destructor must release only its argument; no provider node is inspected
    // after this point.
    for (size_t i = 0; i < plan->count; ++i) {
        const Entry &entry = plan->entries[i];
        if (entry.matches && entry.snapshot.referenceCount == 1) {
            ++completed.destroyedNodes;
            accessors.destroy(accessors.context, entry.snapshot.node);
        }
    }

    *result = completed;
    return Status::Ok;
}

} // namespace SelectiveCache
} // namespace LegacyWiFi

#endif
