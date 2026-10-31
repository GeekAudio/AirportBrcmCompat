// Accessors for the fixed El Capitan provider's intrusive scan-cache nodes.
// Provider/child image admission and WorkLoop ownership belong to the caller.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_CACHE_ACCESS_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_CACHE_ACCESS_HPP

#include "network_identity.hpp"
#include "selective_cache.hpp"

namespace LegacyWiFi { namespace CacheAccess {

constexpr size_t ManagerHeadOffset = 0x18;
constexpr size_t ManagerSize = 0xb0;
constexpr size_t NodeSize = 0xc0;
constexpr size_t PreviousLinkOffset = 8;
constexpr size_t ReferenceCountOffset = 0x10;
constexpr size_t ResultOffset = 0x18;
static_assert(sizeof(uintptr_t) == 8, "the pinned cache uses x86_64 pointers");
static_assert(ResultOffset + ScanBridge::KernelHeaderSize == 0xb0,
              "the copied result ends before provider bookkeeping fields");

// read must either copy the entire requested range or report failure. It must
// validate readability and never invoke provider callbacks. write/destroy are
// non-failing, non-reentrant operations on already admitted allocations; their
// exact constraints are those of SelectiveCache::Accessors. The read callback
// is not a substitute for proving the manager owns the nodes being inspected.
struct Memory {
    void *context = nullptr;
    bool (*read)(void *, uintptr_t, void *, size_t) = nullptr;
    void (*write)(void *, uintptr_t, const void *, size_t) = nullptr;
    void (*destroy)(void *, uintptr_t) = nullptr;
    // Establish exact allocation starts/sizes and that the IE allocation is
    // owned by this node. A no-fault read or generic heap-membership check is
    // insufficient: destroy later passes this exact pointer/size to IOFree.
    bool (*ownsAllocations)(void *, uintptr_t node, size_t nodeSize,
                            uintptr_t ie, size_t ieSize) = nullptr;
};

inline bool range(uintptr_t address, size_t size) {
    return address && size && size - 1 <= UINTPTR_MAX - address;
}
inline bool nodeAddress(uintptr_t address) {
    return range(address, NodeSize) && (address % alignof(uintptr_t)) == 0;
}
inline bool overlap(uintptr_t left,size_t leftSize,uintptr_t right,size_t rightSize) {
    return left<=right ? right-left<leftSize : left-right<rightSize;
}

// Its lifetime encloses preflight and commit. Only a caller with a verified
// provider, verified child, live manager/interface binding and continuously
// held controller WorkLoop may construct an enabled context. The context and
// all its configuration/callback fields must remain unchanged until commit
// returns. This adapter
// alone cannot prove those prerequisites and is not an installer.
struct Context {
    uintptr_t manager = 0;
    NetworkIdentity::Source source = NetworkIdentity::Source::Unknown;
    Memory memory {};

    bool valid() const {
        return range(manager, ManagerSize) &&
            manager % alignof(uintptr_t) == 0 && memory.read && memory.write &&
            memory.destroy && memory.ownsAllocations &&
            (source == NetworkIdentity::Source::Pinned4331 ||
                              source == NetworkIdentity::Source::Pinned43224);
    }
    SelectiveCache::LinkSlot headSlot() const {
        return valid() ? reinterpret_cast<void *>(manager + ManagerHeadOffset) : nullptr;
    }

    static SelectiveCache::Status readLink(void *opaque, SelectiveCache::LinkSlot slot,
                                         SelectiveCache::Node *output) {
        auto *self = static_cast<Context *>(opaque);
        const uintptr_t address = reinterpret_cast<uintptr_t>(slot);
        if (!self || !self->valid() || !output ||
            !range(address, sizeof(uintptr_t)) || address % alignof(uintptr_t))
            return SelectiveCache::Status::AccessFailure;
        uintptr_t next = 0;
        if (!self->memory.read(self->memory.context, address, &next, sizeof(next)))
            return SelectiveCache::Status::AccessFailure;
        if (next && !nodeAddress(next)) return SelectiveCache::Status::CorruptList;
        *output = reinterpret_cast<void *>(next);
        return SelectiveCache::Status::Ok;
    }

    static SelectiveCache::Status inspect(void *opaque, SelectiveCache::Node node,
                                        SelectiveCache::Snapshot *output) {
        auto *self = static_cast<Context *>(opaque);
        const uintptr_t address = reinterpret_cast<uintptr_t>(node);
        if (!self || !self->valid() || !output || !nodeAddress(address))
            return SelectiveCache::Status::AccessFailure;
        uint8_t bytes[NodeSize] {};
        if (!self->memory.read(self->memory.context, address, bytes, sizeof(bytes)))
            return SelectiveCache::Status::AccessFailure;
        const uint8_t *header = bytes + ResultOffset;
        const size_t ieLength = ScanBridge::read16(header + ScanBridge::IELengthOffset);
        // A zero-length record has no owned IE allocation. The provider's
        // destructor skips its pointer field entirely in that case, and the
        // copied legacy header may retain an ignored value there. Preserve
        // that field, but query the allocation registry with canonical (0,0).
        // A previously registered nonempty allocation still cannot match it.
        const uintptr_t ieAddress = ieLength ? static_cast<uintptr_t>(
            ScanBridge::read64(header + ScanBridge::KernelIEPointerOffset)) : 0;
        if (ieLength > ScanBridge::MaximumIEBytes ||
            static_cast<bool>(ieLength) != static_cast<bool>(ieAddress) ||
            (ieLength && (!range(ieAddress, ieLength) ||
                          overlap(ieAddress,ieLength,address,NodeSize) ||
                          overlap(ieAddress,ieLength,self->manager,ManagerSize))) ||
            !self->memory.ownsAllocations(self->memory.context,address,NodeSize,
                                          ieAddress,ieLength))
            return SelectiveCache::Status::InvalidIdentity;

        // Do not pass the pointer-bearing header to the identity decoder.
        // Copy only its scalar prefix and own all referenced IE bytes first.
        uint8_t fixed[ScanBridge::FixedLegacyResultSize] {};
        memcpy(fixed, header, ScanCompat::IEOffset);
        if (ieLength && !self->memory.read(self->memory.context, ieAddress,
                                          fixed + ScanCompat::IEOffset, ieLength)) {
            memset(fixed, 0, sizeof(fixed));
            return SelectiveCache::Status::AccessFailure;
        }
        SelectiveCache::Snapshot snapshot {};
        const int decoded = NetworkIdentity::decode(self->source, fixed, sizeof(fixed),
                                                    &snapshot.identity);
        memset(fixed, 0, sizeof(fixed));
        if (decoded) return SelectiveCache::networkMatchStatus(decoded);
        snapshot.node = node;
        snapshot.nextSlot = node; // The node's first field is its next pointer.
        snapshot.previousLink = reinterpret_cast<void *>(static_cast<uintptr_t>(
            ScanBridge::read64(bytes + PreviousLinkOffset)));
        snapshot.referenceCount = ScanBridge::read32(bytes + ReferenceCountOffset);
        *output = snapshot;
        return SelectiveCache::Status::Ok;
    }

    static void writeLink(void *opaque, SelectiveCache::LinkSlot slot,
                          SelectiveCache::Node value) {
        auto &self = *static_cast<Context *>(opaque);
        const uintptr_t pointer = reinterpret_cast<uintptr_t>(value);
        self.memory.write(self.memory.context, reinterpret_cast<uintptr_t>(slot),
                          &pointer, sizeof(pointer));
    }
    static void writePreviousLink(void *opaque, SelectiveCache::Node node,
                                  SelectiveCache::LinkSlot value) {
        auto &self = *static_cast<Context *>(opaque);
        const uintptr_t pointer = reinterpret_cast<uintptr_t>(value);
        self.memory.write(self.memory.context,
                          reinterpret_cast<uintptr_t>(node) + PreviousLinkOffset,
                          &pointer, sizeof(pointer));
    }
    static void writeReferenceCount(void *opaque, SelectiveCache::Node node, uint32_t value) {
        auto &self = *static_cast<Context *>(opaque);
        self.memory.write(self.memory.context,
                          reinterpret_cast<uintptr_t>(node) + ReferenceCountOffset,
                          &value, sizeof(value));
    }
    static void destroy(void *opaque, SelectiveCache::Node node) {
        auto &self = *static_cast<Context *>(opaque);
        self.memory.destroy(self.memory.context, reinterpret_cast<uintptr_t>(node));
    }
    SelectiveCache::Accessors accessors() {
        if (!valid()) return {};
        return {this, readLink, inspect, writeLink, writePreviousLink,
                writeReferenceCount, destroy};
    }
};

} } // namespace LegacyWiFi::CacheAccess
#endif
