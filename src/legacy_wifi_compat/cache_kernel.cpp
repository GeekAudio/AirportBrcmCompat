#include "cache_kernel.hpp"
#include "cache_access.hpp"
#include "cache_provider_contract.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#include <IOKit/IOLocks.h>
#include <machine/machine_routines.h>
#include <string.h>

namespace LegacyWiFi { namespace CacheKernel { namespace {
namespace C = CacheProviderContract;
namespace R = CacheAllocationRegistry;
constexpr size_t OwnerCapacity = 16;
constexpr size_t AllocationCapacity = 1024;
constexpr uintptr_t UpdateCacheReturn = 0x61ed6;
constexpr uintptr_t ManagerInitReturn = C::FinishAttachManagerInitReturnPC;
constexpr size_t ControllerOffset = 0x50;
constexpr size_t InterfaceOffset = 0x58;
constexpr size_t WorkLoopOffset = 0x60;
constexpr size_t TimerOffset = 0x68;
constexpr size_t RetainedProviderOffset = 0x78;
constexpr size_t ManagerPrefixSize = RetainedProviderOffset + sizeof(uintptr_t);

using ManagerInit = bool (*)(void *, void *, void *);
using ManagerFree = void (*)(void *);
// The audited caller ignores RAX. Preserve its opaque value through the
// wrapper; do not invent a status or claim an unavailable C++ return type.
using UpdateCache = uintptr_t (*)(void *, void *, void *);
using ReleaseCacheNode = void (*)(void *);
using InterfaceDetach = void (*)(void *, uint32_t, void *);
ManagerInit originalInit = nullptr;
ManagerFree originalFree = nullptr;
UpdateCache originalUpdate = nullptr;
ReleaseCacheNode originalRelease = nullptr;
InterfaceDetach originalDetach = nullptr;
API api {};
IOSimpleLock *registryLock = nullptr;
R::Registry<AllocationCapacity, OwnerCapacity> allocations;
uint32_t active = 0;
bool attempted = false;
uintptr_t expectedUpdateReturn = 0;
uintptr_t expectedInitReturn = 0;
uint64_t nextGeneration = 1;
// A conservative transition fence, separate from manager allocation epochs.
// Never publish an init observed across any provider detach. The official
// IONetworkStack already serializes same-interface attach/termination; this
// also detects a reentrant or unrelated detach during admission callbacks.
uint64_t detachEpoch = 1;
uint64_t detaching = 0;

struct Owner {
    OwnerKey key {};
    void *controller = nullptr;
    void *interface = nullptr;
    void *workLoop = nullptr;
    void *timer = nullptr;
    Source source = Source::Unknown;
    bool unavailable = false;
    bool keeper = false;
};
Owner owners[OwnerCapacity] {};

__attribute__((noinline)) void routedRelease(void *node);

struct PruneMemory {
    OwnerKey owner {};
    Source source = Source::Unknown;
};

bool pruneRead(void *, uintptr_t address, void *destination, size_t size) {
    return ScanKernelIdentity::copyOwnedWiredMemory(address, destination, size);
}
void pruneWrite(void *, uintptr_t address, const void *source, size_t size) {
    // SelectiveCache invokes writers only after the full list, every owner
    // tuple, and the complete survivor topology have been revalidated under
    // the caller's continuously held native WorkLoop gate.
    memcpy(reinterpret_cast<void *>(address), source, size);
}
void pruneDestroy(void *, uintptr_t node) {
    // This wrapper retires the exact allocation tuple before invoking the
    // original provider destructor/free routine.
    routedRelease(reinterpret_cast<void *>(node));
}
bool pruneOwns(void *opaque, uintptr_t node, size_t nodeSize,
               uintptr_t ie, size_t ieSize) {
    const auto *memory = static_cast<const PruneMemory *>(opaque);
    if (!memory) return false;
    const Tuple tuple {node, nodeSize, ie, ieSize};
    return CacheKernel::ownsAllocations(memory->owner, memory->source, tuple);
}

class Guard {
public:
    Guard() : restore(IOSimpleLockLockDisableInterrupt(registryLock)) {}
    ~Guard() { IOSimpleLockUnlockEnableInterrupt(registryLock, restore); }
    Guard(const Guard &) = delete;
    Guard &operator=(const Guard &) = delete;
private:
    IOInterruptState restore;
};

bool safeThreadContext() {
    return !ml_at_interrupt_context() && ml_get_interrupts_enabled();
}
bool sameKey(const OwnerKey &a, const OwnerKey &b) {
    return a.manager == b.manager && a.generation == b.generation;
}
Owner *findOwner(uintptr_t manager) {
    for (auto &entry : owners) if (entry.key.manager == manager) return &entry;
    return nullptr;
}
void invalidate(Owner &entry) {
    entry.unavailable = true;
    (void)allocations.retireOwner(entry.key);
}
void invalidateManager(uintptr_t manager) {
    Guard guard;
    if (auto *entry = findOwner(manager)) invalidate(*entry);
}
void invalidateOwner(const OwnerKey &key) {
    Guard guard;
    if (auto *entry = findOwner(key.manager))
        if (sameKey(entry->key, key)) invalidate(*entry);
}

void recordInitialized(void *manager, void *controller, void *interface, uintptr_t caller,
                       uint64_t initializationEpoch) {
    if (!ready() || !initializationEpoch || caller != expectedInitReturn || !manager || !controller ||
        !interface || !safeThreadContext()) return;
    const Source source = api.classifyInitialization(controller, interface);
    if (source != Source::Pinned4331 && source != Source::Pinned43224) return;
    // The complete finishAttach guard proves a fresh manager allocation and
    // this successful initialization call. The manager retains +0x78; require
    // it to be the controller so the raw +0x50 field also stays alive. +0x58 is
    // raw: only the live detach argument or an explicit lease may use it later.
    uint8_t bytes[ManagerPrefixSize] {};
    if (!ScanKernelIdentity::copyOwnedWiredMemory(reinterpret_cast<uintptr_t>(manager),
                                                bytes, sizeof(bytes))) return;
    if (ScanBridge::read64(bytes + ControllerOffset) != reinterpret_cast<uintptr_t>(controller) ||
        ScanBridge::read64(bytes + InterfaceOffset) != reinterpret_cast<uintptr_t>(interface) ||
        ScanBridge::read64(bytes + RetainedProviderOffset) != reinterpret_cast<uintptr_t>(controller) ||
        ScanBridge::read64(bytes + C::ManagerCacheHeadOffset) != 0 ||
        ScanBridge::read64(bytes + C::PendingRequestHeadOffset) != 0) return;
    auto *loop = reinterpret_cast<void *>(ScanBridge::read64(bytes + WorkLoopOffset));
    auto *timer = reinterpret_cast<void *>(ScanBridge::read64(bytes + TimerOffset));
    if (!loop || !timer || !api.validateInitialization(manager, controller, interface, loop, timer))
        return;
    uintptr_t nativeManager = 0;
    const uintptr_t interfaceAddress = reinterpret_cast<uintptr_t>(interface);
    if (interfaceAddress > UINTPTR_MAX - ProviderContract::InterfaceScanManagerOffset ||
        !ScanKernelIdentity::copyOwnedWiredMemory(
            interfaceAddress + ProviderContract::InterfaceScanManagerOffset,
            &nativeManager, sizeof(nativeManager)) ||
        nativeManager != reinterpret_cast<uintptr_t>(manager)) return;
    api.retainObject(manager); // Native initializer's caller still owns it.
    bool recorded = false;
    {
        Guard guard;
        if (auto *previous = findOwner(reinterpret_cast<uintptr_t>(manager))) {
            invalidate(*previous);
        } else if (nextGeneration && detachEpoch == initializationEpoch && !detaching) {
            for (auto &entry : owners) {
                if (entry.key.manager) continue;
                entry.key = {reinterpret_cast<uintptr_t>(manager), nextGeneration};
                nextGeneration = nextGeneration == UINT64_MAX ? 0 : nextGeneration + 1;
                entry.controller = controller;
                entry.interface = interface;
                entry.workLoop = loop;
                entry.timer = timer;
                entry.source = source;
                entry.unavailable = false;
                entry.keeper = true;
                recorded = true;
                break;
            }
        }
    }
    if (!recorded) api.releaseObject(manager);
}

void recordAllocation(void *manager, void *node, uintptr_t caller) {
    if (!ready() || !manager) return;
    const uintptr_t managerAddress = reinterpret_cast<uintptr_t>(manager);
    if (caller != expectedUpdateReturn || !node || !safeThreadContext()) {
        invalidateManager(managerAddress);
        return;
    }
    Owner observed {};
    {
        Guard guard;
        const auto *entry = findOwner(managerAddress);
        if (!entry || entry->unavailable || !entry->keeper) return; // No adoption of an old cache.
        observed = *entry;
    }
    // Exact scanDone call provenance proves a fresh node allocation and any
    // nonempty IE allocation. No-fault copy is only an exact read, not proof.
    uint8_t bytes[C::CacheNodeSize] {};
    const uintptr_t address = reinterpret_cast<uintptr_t>(node);
    if (!CacheAccess::nodeAddress(address) ||
        !ScanKernelIdentity::copyOwnedWiredMemory(address, bytes, sizeof(bytes))) {
        invalidateOwner(observed.key);
        return;
    }
    const size_t length = ScanBridge::read16(bytes + C::CacheNodeIELengthOffset);
    const uintptr_t ie = length ? ScanBridge::read64(bytes + C::CacheNodeIEPointerOffset) : 0;
    const Tuple tuple {address, sizeof(bytes), ie, length};
    const bool shape = ScanBridge::read64(bytes) == 0 &&
        ScanBridge::read64(bytes + C::CacheNodePreviousLinkOffset) == 0 &&
        ScanBridge::read32(bytes + C::CacheNodeReferenceCountOffset) == 0 &&
        !CacheAccess::overlap(address, sizeof(bytes), managerAddress, C::ScanManagerInstanceSize) &&
        (!length || !CacheAccess::overlap(ie, length, managerAddress, C::ScanManagerInstanceSize));
    Guard guard;
    auto *entry = findOwner(managerAddress);
    if (!entry || entry->unavailable || !sameKey(entry->key, observed.key)) return;
    if (!shape || allocations.registerAllocation(entry->key, entry->source, tuple) != R::Status::Ok)
        invalidate(*entry);
}

__attribute__((noinline)) bool routedInit(void *manager, void *controller, void *interface) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    const bool candidate = ready() && caller == expectedInitReturn && manager &&
        controller && interface && safeThreadContext();
    uint64_t initializationEpoch = 0;
    // The admitted finishAttach allocates a new manager before its sole init.
    // Reinitializing a keeper-backed object would replace its loop/timer/raw
    // interface while leases still protect the previous binding. Refuse that
    // invalid lifecycle, preserve retirement handles, and never re-admit it.
    if (registryLock && manager) {
        Guard guard;
        if (auto *entry = findOwner(reinterpret_cast<uintptr_t>(manager))) {
            invalidate(*entry);
            return false;
        }
        if (candidate && detachEpoch && !detaching) {
            // Exact finishAttach call provenance supplies live freshly-created
            // arguments. Its native IONetworkStack lifecycle excludes same-
            // interface detach during attach. Acquire these before the native
            // initializer; a later observed transition cannot make post-init
            // copies/retains access a manager freed by our detach callback.
            api.retainObject(manager);
            api.retainObject(interface);
            api.retainObject(controller);
            initializationEpoch = detachEpoch;
        }
    }
    const bool result = originalInit ? originalInit(manager, controller, interface) : false;
    if (result) recordInitialized(manager, controller, interface, caller, initializationEpoch);
    if (initializationEpoch) {
        api.releaseObject(manager);
        api.releaseObject(interface);
        api.releaseObject(controller);
    }
    return result;
}
__attribute__((noinline)) void routedFree(void *manager) {
    if (registryLock && manager) {
        Guard guard;
        if (auto *entry = findOwner(reinterpret_cast<uintptr_t>(manager))) {
            (void)allocations.retireOwner(entry->key);
            *entry = Owner {};
        }
    }
    // The original drains requests and cache nodes. Their destructor routes
    // retire individual allocations after owner deactivation. No after-free
    // registry operation may accidentally remove a new object at this address.
    if (originalFree) originalFree(manager);
}
__attribute__((noinline)) uintptr_t routedUpdate(void *manager, void *node, void *request) {
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    recordAllocation(manager, node, caller);
    return originalUpdate ? originalUpdate(manager, node, request) : 0;
}
__attribute__((noinline)) void routedRelease(void *node) {
    if (registryLock && node) {
        Guard guard;
        (void)allocations.retire(reinterpret_cast<uintptr_t>(node));
    }
    // All provider calls run outside the registry spin lock.
    if (originalRelease) originalRelease(node);
}

__attribute__((noinline)) void routedDetach(void *interface, uint32_t options, void *parameter) {
    // Detach is not synchronized with the driver gate. First prevent new
    // leases under the registry lock while each keeper still owns its manager.
    // A local manager hold lets concurrent retirements safely share quiescence.
    struct Retiring { Owner state {}; bool keeper = false; } retiring[OwnerCapacity];
    size_t count = 0;
    bool counted = false;
    if (registryLock && interface) {
        Guard guard;
        detachEpoch = detachEpoch == UINT64_MAX ? 0 : (detachEpoch ? detachEpoch + 1 : 0);
        if (detaching != UINT64_MAX) { ++detaching; counted = true; }
        else detachEpoch = 0; // Exhaustion never re-enables new admission.
        for (auto &entry : owners) {
            if (entry.interface != interface || !entry.keeper) continue;
            invalidate(entry);
            api.retainObject(reinterpret_cast<void *>(entry.key.manager));
            retiring[count++].state = entry;
        }
    }
    if (count) {
        // The original superclass detach can change the provider relation.
        // Keep its live receiver until all deferred manager frees finish.
        api.retainObject(interface);
        for (size_t n = 0; n < count; ++n)
            api.quiesceTimer(retiring[n].state.workLoop, retiring[n].state.timer);
        {
            Guard guard;
            for (size_t n = 0; n < count; ++n) {
                const auto &key = retiring[n].state.key;
                auto *entry = findOwner(key.manager);
                if (!entry || !sameKey(entry->key, key) || !entry->keeper) continue;
                entry->keeper = false;
                retiring[n].keeper = true; // Transfer exactly one keeper hold.
            }
        }
    }
    // Never keep a registry lock or acquired WorkLoop gate across superclass
    // detach. Its native reference may be the last one apart from our holds.
    if (originalDetach) originalDetach(interface, options, parameter);
    for (size_t n = 0; n < count; ++n) {
        void *manager = reinterpret_cast<void *>(retiring[n].state.key.manager);
        if (retiring[n].keeper) api.releaseObject(manager);
        api.releaseObject(manager); // Local retirement hold.
    }
    if (count) api.releaseObject(interface);
    if (counted) {
        Guard guard;
        --detaching;
    }
}
} // namespace

bool ready() { return __atomic_load_n(&active, __ATOMIC_ACQUIRE) != 0; }

bool initialize(KernelPatcher &patcher, size_t index, uintptr_t base, size_t size,
                bool cacheContractVerified, const API &callbacks) {
    if (attempted || !cacheContractVerified || !callbacks.classifyInitialization ||
        !callbacks.validateInitialization || !callbacks.validateBinding ||
        !callbacks.retainObject || !callbacks.releaseObject || !callbacks.quiesceTimer ||
        !base || size <= UpdateCacheReturn || base > UINTPTR_MAX - size) return false;
    attempted = true;
    api = callbacks;
    registryLock = IOSimpleLockAlloc();
    if (!registryLock) return false;
    expectedUpdateReturn = base + UpdateCacheReturn;
    expectedInitReturn = base + ManagerInitReturn;
    // Install retirement before allocation observation, and initialization
    // last. Nothing is registered until all five routes are published.
    KernelPatcher::RouteRequest routes[] = {
        {C::Functions[C::ManagerFree].name, routedFree, originalFree},
        {C::Functions[C::ReleaseCacheNode].name, routedRelease, originalRelease},
        {C::Functions[C::InterfaceDetach].name, routedDetach, originalDetach},
        {C::Functions[C::UpdateCache].name, routedUpdate, originalUpdate},
        {C::Functions[C::ManagerInit].name, routedInit, originalInit}
    };
    for (auto &route : routes) {
        patcher.clearError();
        const bool routed = patcher.routeMultiple(index, &route, 1, base, size);
        const bool good = routed && patcher.getError() == KernelPatcher::Error::NoError;
        patcher.clearError();
        if (!good) return false; // Resident partial detours retain their originals.
    }
    if (!originalInit || !originalFree || !originalUpdate || !originalRelease || !originalDetach)
        return false;
    __atomic_store_n(&active, 1U, __ATOMIC_RELEASE);
    return true;
}

bool owner(void *manager, void *controller, void *interface, Source source, OwnerKey *output) {
    if (!ready() || !manager || !controller || !interface || !output) return false;
    Guard guard;
    const auto *entry = findOwner(reinterpret_cast<uintptr_t>(manager));
    if (!entry || entry->unavailable || !entry->keeper || entry->controller != controller ||
        entry->interface != interface || entry->source != source) return false;
    *output = entry->key;
    return true;
}

bool ownsAllocations(const OwnerKey &key, Source source, const Tuple &tuple) {
    if (!ready()) return false;
    Guard guard;
    const auto *entry = findOwner(key.manager);
    return entry && !entry->unavailable && entry->keeper && sameKey(entry->key, key) && entry->source == source &&
        allocations.ownsExact(key, source, tuple);
}

Lease::~Lease() { reset(); }

bool Lease::acquire(void *c, void *i, Source source) {
    if (heldKey.manager || !ready() || !safeThreadContext() || !c || !i ||
        (source != Source::Pinned4331 && source != Source::Pinned43224)) return false;
    // The caller owns these live arguments. Retaining the interface's raw
    // manager slot instead would race its unsynchronized detach release.
    api.retainObject(c);
    api.retainObject(i);
    {
        Guard guard;
        for (const auto &entry : owners) {
            if (!entry.key.manager || entry.unavailable || !entry.keeper ||
                entry.controller != c || entry.interface != i || entry.source != source) continue;
            api.retainObject(reinterpret_cast<void *>(entry.key.manager));
            heldKey = entry.key;
            controller = c;
            interface = i;
            workLoop = entry.workLoop;
            timer = entry.timer;
            heldSource = source;
            break;
        }
    }
    if (!heldKey.manager) {
        api.releaseObject(i);
        api.releaseObject(c);
        return false;
    }
    if (current()) return true;
    reset();
    return false;
}

bool Lease::current() const {
    if (!heldKey.manager || !ready() || !safeThreadContext()) return false;
    {
        Guard guard;
        const auto *entry = findOwner(heldKey.manager);
        if (!entry || entry->unavailable || !entry->keeper || !sameKey(entry->key, heldKey))
            return false;
    }
    if (!api.validateBinding(manager(), controller, interface, workLoop, timer, heldSource))
        return false;
    uint8_t bytes[ManagerPrefixSize] {};
    uintptr_t nativeManager = 0;
    const uintptr_t interfaceAddress = reinterpret_cast<uintptr_t>(interface);
    if (interfaceAddress > UINTPTR_MAX - ProviderContract::InterfaceScanManagerOffset ||
        !ScanKernelIdentity::copyOwnedWiredMemory(heldKey.manager, bytes, sizeof(bytes)) ||
        !ScanKernelIdentity::copyOwnedWiredMemory(
            interfaceAddress + ProviderContract::InterfaceScanManagerOffset,
            &nativeManager, sizeof(nativeManager)) || nativeManager != heldKey.manager ||
        ScanBridge::read64(bytes + ControllerOffset) != reinterpret_cast<uintptr_t>(controller) ||
        ScanBridge::read64(bytes + InterfaceOffset) != interfaceAddress ||
        ScanBridge::read64(bytes + WorkLoopOffset) != reinterpret_cast<uintptr_t>(workLoop) ||
        ScanBridge::read64(bytes + TimerOffset) != reinterpret_cast<uintptr_t>(timer) ||
        ScanBridge::read64(bytes + RetainedProviderOffset) != reinterpret_cast<uintptr_t>(controller))
        return false;
    Guard guard;
    const auto *entry = findOwner(heldKey.manager);
    return entry && !entry->unavailable && entry->keeper && sameKey(entry->key, heldKey) &&
        entry->controller == controller && entry->interface == interface &&
        entry->workLoop == workLoop && entry->timer == timer && entry->source == heldSource;
}

void Lease::reset() {
    if (!heldKey.manager) return;
    void *m = manager(), *i = interface, *c = controller;
    heldKey = {};
    controller = interface = workLoop = timer = nullptr;
    heldSource = Source::Unknown;
    // The final manager release can remove the timer and run provider free,
    // which still uses its raw interface. Drop that interface reference last.
    api.releaseObject(m);
    api.releaseObject(i);
    api.releaseObject(c);
}

SelectiveCache::Status prune(Lease &lease, const NetworkMatch::Identity &key,
                             SelectiveCache::Entry *scratch, size_t capacity,
                             SelectiveCache::Result *result) {
    if (!result) return SelectiveCache::Status::InvalidArgument;
    *result = SelectiveCache::Result {};
    if (capacity > MaximumPruneNodes)
        return SelectiveCache::Status::CapacityExceeded;
    if (capacity && !scratch) return SelectiveCache::Status::InvalidArgument;
    if (!NetworkMatch::valid(key)) return SelectiveCache::Status::InvalidIdentity;

    // Lease.current enforces the caller's native-gate ownership and rejects
    // stale/revoked bindings before any cache memory is inspected.
    if (!lease.current()) return SelectiveCache::Status::AccessFailure;
    const Source source = lease.source();
    const OwnerKey ownerKey = lease.key();
    void *manager = lease.manager();
    if (!manager || !ownerKey.manager || !ownerKey.generation ||
        ownerKey.manager != reinterpret_cast<uintptr_t>(manager) ||
        (source != Source::Pinned4331 && source != Source::Pinned43224))
        return SelectiveCache::Status::AccessFailure;

    PruneMemory memory {ownerKey, source};
    CacheAccess::Context context;
    context.manager = reinterpret_cast<uintptr_t>(manager);
    context.source = source;
    context.memory = {&memory, pruneRead, pruneWrite, pruneDestroy, pruneOwns};
    if (!context.valid()) return SelectiveCache::Status::AccessFailure;
    const auto accessors = context.accessors();
    if (!accessors.inspect || !accessors.readLink || !accessors.writeLink ||
        !accessors.writePreviousLink || !accessors.writeReferenceCount ||
        !accessors.destroy) return SelectiveCache::Status::AccessFailure;

    // The caller holds the same native WorkLoop gate continuously across this
    // synchronous preflight/commit pair. A concurrent detach may revoke the
    // Lease during read-only validation; recheck before commit so that such a
    // transition still fails without provider writes. Once commit's complete
    // revalidation succeeds, finish its bounded write phase before returning.
    SelectiveCache::Plan plan;
    const auto prepared = SelectiveCache::preflight(
        context.headSlot(), &key, scratch, capacity, MaximumPruneNodes,
        accessors, &plan);
    if (prepared != SelectiveCache::Status::Ok) return prepared;
    if (!lease.current()) return SelectiveCache::Status::AccessFailure;
    return SelectiveCache::commit(&plan, result);
}
} }
