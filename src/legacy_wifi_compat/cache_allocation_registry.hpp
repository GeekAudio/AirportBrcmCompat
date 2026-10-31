// Fixed-capacity proof registry for allocations created by the pinned scan
// cache. It records allocation facts supplied by the adapter; it does not
// infer ownership from a readable address or from bytes stored in a node.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_CACHE_ALLOCATION_REGISTRY_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_CACHE_ALLOCATION_REGISTRY_HPP

#include "network_identity.hpp"

#include <stddef.h>
#include <stdint.h>

namespace LegacyWiFi {
namespace CacheAllocationRegistry {

constexpr size_t CacheNodeAllocationSize = 0xc0;
constexpr size_t MaximumIEAllocationSize = 1024;

struct OwnerKey {
    uintptr_t manager = 0;
    uint64_t generation = 0;
};

struct Tuple {
    uintptr_t node = 0;
    size_t nodeSize = 0;
    uintptr_t ie = 0;
    size_t ieSize = 0;
};

enum class Status : uint8_t {
    Ok,
    InvalidOwner,
    InvalidTuple,
    RangeOverflow,
    IETooLarge,
    UnsupportedSource,
    SourceMismatch,
    OwnerNotFound,
    OwnerRetired,
    ActiveGenerationConflict,
    Duplicate,
    Overlap,
    OwnerCapacityExceeded,
    NodeCapacityExceeded,
    NodeNotFound
};

// All operations are bounded linear scans over caller-selected fixed arrays.
// This class has no allocator, lock, provider callback, or eviction policy.
// The caller serializes registry and owner-state operations with an external
// lock, but holds that lock only while reading or changing this registry/state.
// Never hold a spinlock across a native allocator, provider destructor, or
// native free callback.
//
// OwnerKey::generation must come from an adapter-wide monotonically increasing
// counter and must never wrap or be reused. A retired owner's registered
// allocations remain reserved until retire(node), which must be called under
// the registry lock while the exact node allocation is still live and before
// native destruction begins. Register only after the adapter has received an
// exclusive successful node allocation and, when present, an exclusive
// successful IE allocation; register before publishing the node. Release the
// registry lock before calling the original destructor/free path. Never call
// retire after native free: the allocator may already have reused that address
// and a late retirement could erase the new owner's registration.
template <size_t MaxNodes = 512, size_t MaxOwners = 16>
class Registry {
    static_assert(MaxNodes > 0, "the registry needs node capacity");
    static_assert(MaxOwners > 0, "the registry needs owner capacity");
    static_assert(sizeof(uintptr_t) == 8,
                  "the pinned cache allocation contract is x86_64");

public:
    Registry() = default;
    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;
    Registry(Registry &&) = delete;
    Registry &operator=(Registry &&) = delete;

    Status registerAllocation(const OwnerKey &owner,
                              NetworkIdentity::Source source,
                              const Tuple &tuple) {
        if (!validOwner(owner)) return Status::InvalidOwner;
        if (!supportedSource(source)) return Status::UnsupportedSource;
        const Status tupleStatus = validateTuple(tuple);
        if (tupleStatus != Status::Ok) return tupleStatus;

        size_t ownerIndex = findOwner(owner);
        const bool createOwner = ownerIndex == MaxOwners;
        if (!createOwner) {
            const OwnerEntry &entry = owners_[ownerIndex];
            if (!entry.active) return Status::OwnerRetired;
            if (entry.source != source) return Status::SourceMismatch;
        } else {
            for (size_t i = 0; i < MaxOwners; ++i) {
                const OwnerEntry &entry = owners_[i];
                if (entry.occupied && entry.active &&
                    entry.key.manager == owner.manager &&
                    entry.key.generation != owner.generation)
                    return Status::ActiveGenerationConflict;
            }
            ownerIndex = findFreeOwner();
            if (ownerIndex == MaxOwners) return Status::OwnerCapacityExceeded;
        }

        size_t freeNodeIndex = MaxNodes;
        for (size_t i = 0; i < MaxNodes; ++i) {
            const AllocationEntry &entry = allocations_[i];
            if (!entry.occupied) {
                if (freeNodeIndex == MaxNodes) freeNodeIndex = i;
                continue;
            }
            if (sameOwner(entry.owner, owner) && entry.source == source &&
                sameTuple(entry.tuple, tuple)) return Status::Duplicate;
            if (overlaps(tuple, entry.tuple)) return Status::Overlap;
        }
        if (freeNodeIndex == MaxNodes) return Status::NodeCapacityExceeded;

        // No mutation occurs until all validation, conflict, and capacity
        // checks have succeeded. The remaining writes cannot fail.
        if (createOwner) {
            owners_[ownerIndex].key = owner;
            owners_[ownerIndex].source = source;
            owners_[ownerIndex].active = true;
            owners_[ownerIndex].occupied = true;
        }
        allocations_[freeNodeIndex].owner = owner;
        allocations_[freeNodeIndex].source = source;
        allocations_[freeNodeIndex].tuple = tuple;
        allocations_[freeNodeIndex].occupied = true;
        return Status::Ok;
    }

    // Detached nodes remain registered. The tuple describes actual owned
    // allocations, not ignored bytes in the node header. With no IE allocation
    // the canonical tuple is (ie=0, ieSize=0), even if an unused header pointer
    // is nonzero; a previously registered nonzero IE tuple does not match it.
    // Canonicalize only when the adapter has proof no IE allocation is owned
    // by this node. A still-live prior IE allocation must retain its exact
    // registered tuple; the core will reject a zero-tuple lookup for it.
    // Only a pre-free retire frees ranges for possible later address reuse.
    bool ownsExact(const OwnerKey &owner,
                   NetworkIdentity::Source source,
                   const Tuple &tuple) const {
        if (!validOwner(owner) || !supportedSource(source) ||
            validateTuple(tuple) != Status::Ok) return false;
        const size_t ownerIndex = findOwner(owner);
        if (ownerIndex == MaxOwners) return false;
        const OwnerEntry &ownerEntry = owners_[ownerIndex];
        if (!ownerEntry.active || ownerEntry.source != source) return false;
        for (size_t i = 0; i < MaxNodes; ++i) {
            const AllocationEntry &entry = allocations_[i];
            if (entry.occupied && sameOwner(entry.owner, owner) &&
                entry.source == source && sameTuple(entry.tuple, tuple))
                return true;
        }
        return false;
    }

    // Call under the registry lock only while the exact node allocation is
    // still live and immediately before its verified provider destructor. Then
    // release the lock and call the original destructor/free path. This
    // deliberately does not inspect list membership or request-reference
    // counts; calling it after free creates an address-reuse ABA hazard.
    Status retire(uintptr_t node) {
        if (!node) return Status::InvalidTuple;
        size_t nodeIndex = MaxNodes;
        for (size_t i = 0; i < MaxNodes; ++i) {
            if (allocations_[i].occupied && allocations_[i].tuple.node == node) {
                nodeIndex = i;
                break;
            }
        }
        if (nodeIndex == MaxNodes) return Status::NodeNotFound;

        const OwnerKey owner = allocations_[nodeIndex].owner;
        allocations_[nodeIndex] = AllocationEntry {};
        const size_t ownerIndex = findOwner(owner);
        if (ownerIndex != MaxOwners && !owners_[ownerIndex].active &&
            !hasAllocations(owner))
            owners_[ownerIndex] = OwnerEntry {};
        return Status::Ok;
    }

    // Deactivation prevents all future queries and registrations for this
    // owner generation. Live allocation records remain reserved until their
    // individual pre-free destructor hooks call retire(node). This bounded
    // state transition does not call the manager's native destructor.
    Status retireOwner(const OwnerKey &owner) {
        if (!validOwner(owner)) return Status::InvalidOwner;
        const size_t ownerIndex = findOwner(owner);
        if (ownerIndex == MaxOwners) return Status::OwnerNotFound;
        OwnerEntry &entry = owners_[ownerIndex];
        if (!entry.active) return Status::OwnerRetired;
        entry.active = false;
        if (!hasAllocations(owner)) entry = OwnerEntry {};
        return Status::Ok;
    }

    size_t registeredNodeCount() const {
        size_t count = 0;
        for (size_t i = 0; i < MaxNodes; ++i)
            if (allocations_[i].occupied) ++count;
        return count;
    }

    size_t occupiedOwnerCount() const {
        size_t count = 0;
        for (size_t i = 0; i < MaxOwners; ++i)
            if (owners_[i].occupied) ++count;
        return count;
    }

private:
    struct OwnerEntry {
        OwnerKey key {};
        NetworkIdentity::Source source = NetworkIdentity::Source::Unknown;
        bool occupied = false;
        bool active = false;
    };

    struct AllocationEntry {
        OwnerKey owner {};
        NetworkIdentity::Source source = NetworkIdentity::Source::Unknown;
        Tuple tuple {};
        bool occupied = false;
    };

    OwnerEntry owners_[MaxOwners] {};
    AllocationEntry allocations_[MaxNodes] {};

    static bool supportedSource(NetworkIdentity::Source source) {
        return source == NetworkIdentity::Source::Pinned4331 ||
            source == NetworkIdentity::Source::Pinned43224;
    }

    static bool validOwner(const OwnerKey &owner) {
        return owner.manager != 0 && owner.generation != 0;
    }

    static bool validRange(uintptr_t address, size_t size) {
        return address && size && size - 1 <= UINTPTR_MAX - address;
    }

    static bool rangesOverlap(uintptr_t left, size_t leftSize,
                              uintptr_t right, size_t rightSize) {
        if (!left || !right || !leftSize || !rightSize) return false;
        return left <= right ? right - left < leftSize
                             : left - right < rightSize;
    }

    static Status validateTuple(const Tuple &tuple) {
        if (!tuple.node || tuple.nodeSize != CacheNodeAllocationSize ||
            tuple.node % alignof(uintptr_t) != 0)
            return Status::InvalidTuple;
        if (!validRange(tuple.node, tuple.nodeSize)) return Status::RangeOverflow;
        if (tuple.ieSize > MaximumIEAllocationSize) return Status::IETooLarge;
        if ((tuple.ie == 0) != (tuple.ieSize == 0)) return Status::InvalidTuple;
        if (tuple.ie && !validRange(tuple.ie, tuple.ieSize))
            return Status::RangeOverflow;
        if (tuple.ie && rangesOverlap(tuple.node, tuple.nodeSize,
                                      tuple.ie, tuple.ieSize))
            return Status::Overlap;
        return Status::Ok;
    }

    static bool sameOwner(const OwnerKey &left, const OwnerKey &right) {
        return left.manager == right.manager &&
            left.generation == right.generation;
    }

    static bool sameTuple(const Tuple &left, const Tuple &right) {
        return left.node == right.node && left.nodeSize == right.nodeSize &&
            left.ie == right.ie && left.ieSize == right.ieSize;
    }

    static bool overlaps(const Tuple &left, const Tuple &right) {
        return rangesOverlap(left.node, left.nodeSize,
                             right.node, right.nodeSize) ||
            rangesOverlap(left.node, left.nodeSize,
                          right.ie, right.ieSize) ||
            rangesOverlap(left.ie, left.ieSize,
                          right.node, right.nodeSize) ||
            rangesOverlap(left.ie, left.ieSize,
                          right.ie, right.ieSize);
    }

    size_t findOwner(const OwnerKey &owner) const {
        for (size_t i = 0; i < MaxOwners; ++i)
            if (owners_[i].occupied && sameOwner(owners_[i].key, owner))
                return i;
        return MaxOwners;
    }

    size_t findFreeOwner() const {
        for (size_t i = 0; i < MaxOwners; ++i)
            if (!owners_[i].occupied) return i;
        return MaxOwners;
    }

    bool hasAllocations(const OwnerKey &owner) const {
        for (size_t i = 0; i < MaxNodes; ++i)
            if (allocations_[i].occupied &&
                sameOwner(allocations_[i].owner, owner)) return true;
        return false;
    }
};

} // namespace CacheAllocationRegistry
} // namespace LegacyWiFi

#endif
