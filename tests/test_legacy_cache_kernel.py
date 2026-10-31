"""Exercise the production cache-kernel routes through portable kernel mocks."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

PROJECT = Path(__file__).resolve().parents[1]

KERNEL_PATCHER_STUB = r'''
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

uintptr_t nativeCacheUpdate(void *, void *, void *);
bool nativeCacheManagerInit(void *, void *, void *);
void nativeCacheManagerFree(void *);
void nativeCacheRelease(void *);
void nativeCacheDetach(void *, uint32_t, void *);

class KernelPatcher {
public:
    enum class Error { NoError, RouteFailure };
    struct RouteRequest {
        const char *symbol;
        uintptr_t target;
        void *originalSlot;
        template <typename Target, typename Original>
        RouteRequest(const char *name, Target entry, Original &original)
            : symbol(name), target(reinterpret_cast<uintptr_t>(entry)),
              originalSlot(reinterpret_cast<void *>(&original)) {}
    };

    Error error = Error::NoError;
    unsigned routeCalls = 0;
    unsigned failRouteCall = 0;
    bool routeMultiple(size_t, RouteRequest *request, size_t count,
                       uintptr_t, size_t) {
        if (!request || count != 1) {
            error = Error::RouteFailure;
            return false;
        }
        ++routeCalls;
        uintptr_t original = 0;
        if (!std::strcmp(request->symbol,
                         "__ZN18IO80211ScanManager30initWithControllerAndInterfaceEP17IO80211ControllerP16IO80211Interface"))
            original = reinterpret_cast<uintptr_t>(nativeCacheManagerInit);
        else if (!std::strcmp(request->symbol,
                         "__ZN18IO80211ScanManager4freeEv"))
            original = reinterpret_cast<uintptr_t>(nativeCacheManagerFree);
        else if (!std::strcmp(request->symbol,
                         "__ZN18IO80211ScanManager11updateCacheEP25apple80211scan_cache_nodeP23apple80211scan_req_node"))
            original = reinterpret_cast<uintptr_t>(nativeCacheUpdate);
        else if (!std::strcmp(request->symbol,
                         "__ZL17_releaseCacheNodeP25apple80211scan_cache_node"))
            original = reinterpret_cast<uintptr_t>(nativeCacheRelease);
        else if (!std::strcmp(request->symbol,
                         "__ZN16IO80211Interface23detachFromDataLinkLayerEjPv"))
            original = reinterpret_cast<uintptr_t>(nativeCacheDetach);
        else {
            error = Error::RouteFailure;
            return false;
        }
        std::memcpy(request->originalSlot, &original, sizeof(original));
        // Model a detour that became resident before the patcher reported a
        // late route error. The adapter must leave its trampoline callable.
        if (failRouteCall && routeCalls == failRouteCall) {
            error = Error::RouteFailure;
            return false;
        }
        error = Error::NoError;
        return true;
    }
    Error getError() const { return error; }
    void clearError() { error = Error::NoError; }
};

'''

IOLOCKS_STUB = r'''
#pragma once
#include <cstdint>
struct IOSimpleLock { unsigned marker; };
using IOInterruptState = uintptr_t;
IOSimpleLock *IOSimpleLockAlloc();
IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *);
void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *, IOInterruptState);
'''

MACHINE_ROUTINES_STUB = r'''
#pragma once
bool ml_at_interrupt_context();
bool ml_get_interrupts_enabled();
'''

HARNESS = r'''
#include <cassert>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "src/legacy_wifi_compat/cache_kernel.cpp"

using LegacyWiFi::CacheKernel::Source;
using LegacyWiFi::CacheKernel::OwnerKey;
using LegacyWiFi::CacheKernel::Tuple;
using LegacyWiFi::CacheProviderContract::ScanManagerInstanceSize;
using LegacyWiFi::CacheProviderContract::CacheNodeSize;
using LegacyWiFi::CacheProviderContract::CacheNodeIELengthOffset;
using LegacyWiFi::CacheProviderContract::CacheNodeIEPointerOffset;
using LegacyWiFi::CacheProviderContract::ManagerCacheHeadOffset;
using LegacyWiFi::ProviderContract::InterfaceScanManagerOffset;

extern "C" bool invoke_cache_init(uintptr_t entry, void *manager,
                                  void *controller, void *interface);
extern "C" void cache_init_return_pc();

enum class ObjectKind { Manager, Controller, Interface, WorkLoop, Timer };
struct ObjectState {
    unsigned references = 0;
    ObjectKind kind = ObjectKind::Manager;
    bool live = true;
    bool quiesced = false;
};

static IOSimpleLock fakeLock {1};
static unsigned lockDepth = 0;
static bool interruptsEnabled = true;
static bool interruptContext = false;
static unsigned copyCount = 0;
static unsigned failCopyAt = 0;
static unsigned partialCopyAt = 0;
static bool initResult = true;
static bool initWithPreexistingHead = false;
static bool expectRegisteredAtUpdate = false;
static bool populateCacheOnUpdate = false;
static uint32_t updateNodeReferenceCount = 1;
static bool checkReleaseRetired = false;
static bool managerFreed = false;
static bool updateSawRegistration = false;
static bool freeSawOwnerRetired = false;
static bool detachSawOwnerRetired = false;
static bool initValidationAllowed = true;
static bool bindingValidationAllowed = true;
static bool gateHeld = false;
static bool expectQuiesceBeforeDetach = false;
static bool quarantineManagerOnFree = false;
static bool reuseQuarantinedManager = false;
static bool managerHasKeeper = false;
static bool initReturnPcRelocated = false;
static bool leaseHeldForDetach = false;
static bool detachDuringValidation = false;
static bool unrelatedDetachDuringValidation = false;
static bool validationInterleaveRan = false;
static bool initDuringNativeDetach = false;
static bool nativeDetachInterleaveRan = false;
static bool suppressNativeInitChildRetains = false;
static bool interleavedInitReturned = false;
static bool interleavedInitSawOwner = false;
static bool checkPruneDestroyState = false;
static uintptr_t pruneExpectedHead = 0;
static uintptr_t pruneExpectedDetachedNode = 0;
static uintptr_t pruneExpectedRetainedNode = 0;
static unsigned initCalls = 0;
static unsigned updateCalls = 0;
static unsigned releaseCalls = 0;
static unsigned detachCalls = 0;
static unsigned freeCalls = 0;
static unsigned validationCalls = 0;
static unsigned bindingCalls = 0;
static unsigned quiesceCalls = 0;
static unsigned managerRetainsInLock = 0;
static unsigned objectReleases = 0;
static unsigned unknownReleaseCalls = 0;
static unsigned freedIECalls = 0;
static void *boundManager = nullptr;
static void *boundController = nullptr;
static void *boundInterface = nullptr;
static void *boundWorkLoop = nullptr;
static void *boundTimer = nullptr;
static Source classifiedSource = Source::Pinned4331;
static Source expectedSource = Source::Pinned4331;
static OwnerKey lastOwner {};
static Tuple lastTuple {};
static std::vector<void *> nativeNodes;
static std::vector<void *> managerQuarantine;
static std::unordered_map<void *, ObjectState> objectStates;
static std::unordered_map<void *, unsigned> retainDepths;
static std::unordered_set<uintptr_t> liveIEPointers;

static uintptr_t read64(const void *address) {
    uintptr_t value = 0;
    std::memcpy(&value, address, sizeof(value));
    return value;
}
static void write64(void *address, uintptr_t value) {
    std::memcpy(address, &value, sizeof(value));
}
static void write32(void *address, uint32_t value) {
    std::memcpy(address, &value, sizeof(value));
}
static uint16_t read16(const void *address) {
    uint16_t value = 0;
    std::memcpy(&value, address, sizeof(value));
    return value;
}
static void write16(void *address, uint16_t value) {
    std::memcpy(address, &value, sizeof(value));
}
static Tuple tupleFor(void *node) {
    auto *bytes = static_cast<uint8_t *>(node);
    const size_t length = read16(bytes + CacheNodeIELengthOffset);
    const uintptr_t ie = length ? read64(bytes + CacheNodeIEPointerOffset) : 0;
    return {reinterpret_cast<uintptr_t>(node), CacheNodeSize, ie, length};
}
static LegacyWiFi::NetworkMatch::Identity networkKey(const char *ssid,
                                                       uint16_t modes,
                                                       uint16_t apMode) {
    LegacyWiFi::NetworkMatch::Identity value {};
    const size_t length = std::strlen(ssid);
    assert(length <= LegacyWiFi::NetworkMatch::MaximumSSIDLength);
    value.ssidLength = static_cast<uint8_t>(length);
    std::memcpy(value.ssid, ssid, length);
    value.encryptionModes = modes;
    value.apMode = apMode;
    value.fils = LegacyWiFi::NetworkMatch::FILS::Unknown;
    return value;
}
static std::vector<uint8_t> captureRegions(
        std::initializer_list<std::pair<void *, size_t>> regions) {
    std::vector<uint8_t> result;
    for (const auto &region : regions) {
        const size_t offset = result.size();
        result.resize(offset + region.second);
        std::memcpy(result.data() + offset, region.first, region.second);
    }
    return result;
}
static void *makeObject(size_t size, ObjectKind kind, unsigned references = 1) {
    void *object = std::calloc(1, size);
    assert(object);
    objectStates.emplace(object, ObjectState {references, kind, true, false});
    return object;
}
static void *makeManager() {
    assert(ScanManagerInstanceSize == 0xb0);
    if (reuseQuarantinedManager && !managerQuarantine.empty()) {
        void *manager = managerQuarantine.back();
        managerQuarantine.pop_back();
        std::memset(manager, 0, ScanManagerInstanceSize);
        objectStates.emplace(manager, ObjectState {1, ObjectKind::Manager, true, false});
        reuseQuarantinedManager = false;
        return manager;
    }
    return makeObject(ScanManagerInstanceSize, ObjectKind::Manager);
}
static void prepareNativeObjects(void *manager) {
    boundManager = manager;
    boundController = makeObject(0x100, ObjectKind::Controller);
    boundInterface = makeObject(0x300, ObjectKind::Interface);
    boundWorkLoop = makeObject(0x100, ObjectKind::WorkLoop);
    boundTimer = makeObject(0x100, ObjectKind::Timer);
    gateHeld = true;
}
static ObjectState &objectState(void *object) {
    auto it = objectStates.find(object);
    assert(it != objectStates.end() && it->second.live);
    return it->second;
}
static unsigned referenceCount(void *object) {
    auto it = objectStates.find(object);
    return it == objectStates.end() ? 0 : it->second.references;
}
static bool objectIsLive(void *object) {
    auto it = objectStates.find(object);
    return it != objectStates.end() && it->second.live;
}
static void releaseObject(void *object);
static void retainObject(void *object) {
    assert(lockDepth <= 1);
    ObjectState &state = objectState(object);
    assert(state.references > 0);
    if (lockDepth == 1)
        assert(state.kind == ObjectKind::Manager || state.kind == ObjectKind::Interface ||
               state.kind == ObjectKind::Controller);
    ++state.references;
    if (state.kind == ObjectKind::Manager && lockDepth == 1)
        ++managerRetainsInLock;
    ++retainDepths[object];
}
static void releaseObject(void *object) {
    assert(lockDepth == 0 && object);
    ObjectState &state = objectState(object);
    assert(state.references > 0);
    --state.references;
    ++objectReleases;
    if (state.references != 0) return;
    if (state.kind == ObjectKind::Manager) {
        // Model OSObject reaching zero: the resident ManagerFree route must
        // run the pinned native destructor and free the backing allocation.
        LegacyWiFi::CacheKernel::routedFree(object);
        return;
    }
    state.live = false;
    std::free(object);
    objectStates.erase(object);
}
static void *makeNode(size_t ieLength = 0, uintptr_t ignoredIEPointer = 0) {
    auto *node = static_cast<uint8_t *>(std::calloc(1, CacheNodeSize));
    assert(node);
    auto *header = node + 0x18;
    write32(header, 1);
    write16(header + 0x1a, 1);
    header[0x60] = 1;
    header[0x61] = 'x';
    header[0x88] = 0;
    if (ieLength) {
        void *ie = std::malloc(ieLength);
        assert(ie);
        std::memset(ie, 0x5a, ieLength);
        write64(node + CacheNodeIEPointerOffset, reinterpret_cast<uintptr_t>(ie));
        liveIEPointers.insert(reinterpret_cast<uintptr_t>(ie));
    } else if (ignoredIEPointer) {
        write64(node + CacheNodeIEPointerOffset, ignoredIEPointer);
    }
    write16(node + CacheNodeIELengthOffset, static_cast<uint16_t>(ieLength));
    write16(header + 0x8a, static_cast<uint16_t>(ieLength));
    return node;
}
static void setNodeIdentity(void *rawNode, const char *ssid, uint16_t capability,
                            bool includeRSN) {
    auto *node = static_cast<uint8_t *>(rawNode);
    auto *header = node + 0x18;
    const size_t length = std::strlen(ssid);
    assert(length <= 32);
    write32(header, 1);
    write16(header + 0x1a, capability);
    header[0x60] = static_cast<uint8_t>(length);
    std::memset(header + 0x61, 0, 32);
    std::memcpy(header + 0x61, ssid, length);
    header[0x88] = 0;
    if (includeRSN) {
        assert(read16(node + CacheNodeIELengthOffset) == 3);
        auto *ie = reinterpret_cast<uint8_t *>(read64(node + CacheNodeIEPointerOffset));
        ie[0] = 48;
        ie[1] = 1;
        ie[2] = 0;
    } else {
        assert(read16(node + CacheNodeIELengthOffset) == 0);
    }
}
static Source classify(void *controller, void *interface) {
    assert(lockDepth == 0);
    if (controller != boundController || interface != boundInterface)
        return Source::Unknown;
    return classifiedSource;
}
static bool validateInitialization(void *manager, void *controller, void *interface,
                                   void *workLoop, void *timer) {
    assert(lockDepth == 0);
    ++validationCalls;
    if (!initValidationAllowed || manager != boundManager ||
        controller != boundController || interface != boundInterface ||
        workLoop != boundWorkLoop || timer != boundTimer ||
        !objectIsLive(manager) || !objectIsLive(controller) ||
        !objectIsLive(interface) || !objectIsLive(workLoop) || !objectIsLive(timer))
        return false;
    const auto *bytes = static_cast<const uint8_t *>(manager);
    const bool valid = read64(bytes + 0x50) == reinterpret_cast<uintptr_t>(controller) &&
        read64(bytes + 0x58) == reinterpret_cast<uintptr_t>(interface) &&
        read64(bytes + 0x60) == reinterpret_cast<uintptr_t>(workLoop) &&
        read64(bytes + 0x68) == reinterpret_cast<uintptr_t>(timer) &&
        read64(bytes + 0x78) == reinterpret_cast<uintptr_t>(controller) &&
        read64(static_cast<uint8_t *>(interface) + InterfaceScanManagerOffset) ==
            reinterpret_cast<uintptr_t>(manager);
    if (valid && !validationInterleaveRan &&
        (detachDuringValidation || unrelatedDetachDuringValidation)) {
        validationInterleaveRan = true;
        if (detachDuringValidation) {
            LegacyWiFi::CacheKernel::routedDetach(interface, 0, nullptr);
            // The initializer's pre-original holds must keep the object and
            // its arguments alive until admission rejects this old epoch.
            assert(objectIsLive(manager));
            assert(referenceCount(manager) == 1);
            assert(read64(static_cast<uint8_t *>(interface) +
                          InterfaceScanManagerOffset) == 0);
        } else {
            void *unrelated = makeObject(0x300, ObjectKind::Interface);
            LegacyWiFi::CacheKernel::routedDetach(unrelated, 0, nullptr);
            releaseObject(unrelated);
            assert(objectIsLive(manager));
            assert(read64(static_cast<uint8_t *>(interface) +
                          InterfaceScanManagerOffset) ==
                   reinterpret_cast<uintptr_t>(manager));
        }
    }
    return valid;
}
static bool validateBinding(void *manager, void *controller, void *interface,
                            void *workLoop, void *timer, Source source) {
    assert(lockDepth == 0);
    ++bindingCalls;
    if (!bindingValidationAllowed || !gateHeld || source != classifiedSource ||
        manager != boundManager || controller != boundController ||
        interface != boundInterface || workLoop != boundWorkLoop || timer != boundTimer ||
        !objectIsLive(manager) || !objectIsLive(controller) || !objectIsLive(interface) ||
        !objectIsLive(workLoop) || !objectIsLive(timer)) return false;
    const auto *bytes = static_cast<const uint8_t *>(manager);
    return read64(bytes + 0x50) == reinterpret_cast<uintptr_t>(controller) &&
        read64(bytes + 0x58) == reinterpret_cast<uintptr_t>(interface) &&
        read64(bytes + 0x60) == reinterpret_cast<uintptr_t>(workLoop) &&
        read64(bytes + 0x68) == reinterpret_cast<uintptr_t>(timer) &&
        read64(bytes + 0x78) == reinterpret_cast<uintptr_t>(controller) &&
        read64(static_cast<uint8_t *>(interface) + InterfaceScanManagerOffset) ==
            reinterpret_cast<uintptr_t>(manager);
}
static void quiesceTimer(void *workLoop, void *timer) {
    assert(lockDepth == 0);
    ++quiesceCalls;
    assert(workLoop == boundWorkLoop && timer == boundTimer);
    assert(objectIsLive(workLoop) && objectIsLive(timer));
    objectState(timer).quiesced = true;
}
static LegacyWiFi::CacheKernel::API callbacks() {
    return {classify, validateInitialization, validateBinding,
            retainObject, releaseObject, quiesceTimer};
}

IOSimpleLock *IOSimpleLockAlloc() { return &fakeLock; }
IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock == &fakeLock);
    assert(lockDepth == 0);
    const IOInterruptState oldState = interruptsEnabled ? 1 : 0;
    interruptsEnabled = false;
    ++lockDepth;
    return oldState;
}
void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock, IOInterruptState state) {
    assert(lock == &fakeLock);
    assert(lockDepth == 1);
    --lockDepth;
    interruptsEnabled = state != 0;
}
bool ml_at_interrupt_context() { return interruptContext; }
bool ml_get_interrupts_enabled() { return interruptsEnabled; }

namespace ScanKernelIdentity {
bool copyOwnedWiredMemory(uintptr_t address, void *destination, size_t size) {
    assert(lockDepth == 0); // The production reader must run outside the spin lock.
    ++copyCount;
    if (!address || !destination || !size || size > MaxOwnedWiredRead) return false;
    if (copyCount == partialCopyAt) {
        std::memcpy(destination, reinterpret_cast<const void *>(address), size / 2);
        return false;
    }
    if (copyCount == failCopyAt) return false;
    std::memcpy(destination, reinterpret_cast<const void *>(address), size);
    return true;
}
}

bool nativeCacheManagerInit(void *manager, void *controller, void *interface) {
    assert(lockDepth == 0); // Native provider calls must not be under our lock.
    ++initCalls;
    auto *bytes = static_cast<uint8_t *>(manager);
    std::memset(bytes, 0, ScanManagerInstanceSize);
    write64(bytes + 0x50, reinterpret_cast<uintptr_t>(controller));
    write64(bytes + 0x58, reinterpret_cast<uintptr_t>(interface));
    write64(bytes + 0x60, reinterpret_cast<uintptr_t>(boundWorkLoop));
    write64(bytes + 0x68, reinterpret_cast<uintptr_t>(boundTimer));
    write64(bytes + 0x78, reinterpret_cast<uintptr_t>(controller));
    write64(static_cast<uint8_t *>(interface) + InterfaceScanManagerOffset,
            reinterpret_cast<uintptr_t>(manager));
    // The audited native manager holds the controller and timer objects for
    // its lifetime; WorkLoop and timer storage are independent mock objects.
    if (!suppressNativeInitChildRetains) {
        retainObject(controller);
        retainObject(boundWorkLoop);
        retainObject(boundTimer);
    }
    if (initWithPreexistingHead)
        write64(bytes + LegacyWiFi::CacheProviderContract::ManagerCacheHeadOffset,
                reinterpret_cast<uintptr_t>(bytes + 0x80));
    return initResult;
}

uintptr_t nativeCacheUpdate(void *manager, void *node, void *) {
    assert(lockDepth == 0); // Original update executes after registry unlock.
    ++updateCalls;
    OwnerKey key {};
    const bool hasOwner = LegacyWiFi::CacheKernel::owner(
        manager, boundController, boundInterface, expectedSource, &key);
    assert(hasOwner == expectRegisteredAtUpdate);
    updateSawRegistration = hasOwner;
    if (hasOwner) {
        const Tuple tuple = tupleFor(node);
        assert(LegacyWiFi::CacheKernel::ownsAllocations(key, expectedSource, tuple));
        lastOwner = key;
        lastTuple = tuple;
    }
    nativeNodes.push_back(node); // The original provider now owns the inserted node.
    if (populateCacheOnUpdate) {
        auto *managerBytes = static_cast<uint8_t *>(manager);
        auto *nodeBytes = static_cast<uint8_t *>(node);
        const uintptr_t headSlot = reinterpret_cast<uintptr_t>(managerBytes +
            ManagerCacheHeadOffset);
        const uintptr_t oldHead = read64(reinterpret_cast<void *>(headSlot));
        write64(nodeBytes, oldHead);
        write64(nodeBytes + 8, headSlot);
        if (oldHead) write64(reinterpret_cast<void *>(oldHead + 8),
                             reinterpret_cast<uintptr_t>(nodeBytes));
        write64(reinterpret_cast<void *>(headSlot), reinterpret_cast<uintptr_t>(nodeBytes));
        write32(nodeBytes + 0x10, updateNodeReferenceCount);
    }
    return UINT64_C(0x123456789abcdef0); // Opaque machine return; no status meaning.
}

void nativeCacheRelease(void *node) {
    assert(lockDepth == 0); // The destructor/free executes after registry unlock.
    ++releaseCalls;
    auto *bytes = static_cast<uint8_t *>(node);
    const size_t length = read16(bytes + CacheNodeIELengthOffset);
    const uintptr_t ie = length ? read64(bytes + CacheNodeIEPointerOffset) : 0;
    if (checkPruneDestroyState) {
        assert(reinterpret_cast<uintptr_t>(node) == pruneExpectedDetachedNode);
        assert(read64(static_cast<uint8_t *>(boundManager) +
                      ManagerCacheHeadOffset) == pruneExpectedHead);
        assert(read64(bytes) == 0 && read64(bytes + 8) == 0);
        assert(LegacyWiFi::ScanBridge::read32(bytes + 0x10) == 0);
        auto *retained = reinterpret_cast<uint8_t *>(pruneExpectedRetainedNode);
        assert(retained && read64(retained) == 0 && read64(retained + 8) == 0);
        assert(LegacyWiFi::ScanBridge::read32(retained + 0x10) == 2);
        auto *survivor = reinterpret_cast<uint8_t *>(pruneExpectedHead);
        assert(survivor && read64(survivor + 8) ==
            reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(boundManager) +
                                        ManagerCacheHeadOffset));
    }
    if (checkReleaseRetired && lastOwner.manager) {
        assert(!LegacyWiFi::CacheKernel::ownsAllocations(lastOwner, expectedSource,
                                                         tupleFor(node)));
    }
    auto it = std::find(nativeNodes.begin(), nativeNodes.end(), node);
    if (it == nativeNodes.end()) ++unknownReleaseCalls;
    else nativeNodes.erase(it);
    if (length) {
        assert(liveIEPointers.erase(ie) == 1);
        std::free(reinterpret_cast<void *>(ie));
        ++freedIECalls;
    }
    std::free(node);
}

void nativeCacheManagerFree(void *manager) {
    assert(lockDepth == 0); // Provider teardown executes outside our lock.
    ++freeCalls;
    OwnerKey key {};
    freeSawOwnerRetired = !LegacyWiFi::CacheKernel::owner(
        manager, boundController, boundInterface, expectedSource, &key);
    assert(freeSawOwnerRetired);
    if (lastOwner.manager)
        assert(!LegacyWiFi::CacheKernel::ownsAllocations(lastOwner, expectedSource,
                                                         lastTuple));
    while (!nativeNodes.empty())
        LegacyWiFi::CacheKernel::routedRelease(nativeNodes.back());
    auto *bytes = static_cast<uint8_t *>(manager);
    void *controller = reinterpret_cast<void *>(read64(bytes + 0x78));
    void *workLoop = reinterpret_cast<void *>(read64(bytes + 0x60));
    void *timer = reinterpret_cast<void *>(read64(bytes + 0x68));
    void *rawInterface = reinterpret_cast<void *>(read64(bytes + 0x58));
    if (rawInterface) assert(objectIsLive(rawInterface));
    if (timer) releaseObject(timer);
    if (workLoop) releaseObject(workLoop);
    if (controller) releaseObject(controller);
    auto state = objectStates.find(manager);
    assert(state != objectStates.end() && state->second.kind == ObjectKind::Manager &&
           state->second.references == 0);
    state->second.live = false;
    objectStates.erase(state);
    managerFreed = true;
    if (quarantineManagerOnFree) managerQuarantine.push_back(manager);
    else std::free(manager);
}

void nativeCacheDetach(void *interface, uint32_t, void *) {
    assert(lockDepth == 0); // The superclass detach path runs outside our lock.
    ++detachCalls;
    auto *bytes = static_cast<uint8_t *>(interface);
    void *manager = reinterpret_cast<void *>(read64(bytes + InterfaceScanManagerOffset));
    if (manager && initDuringNativeDetach && !nativeDetachInterleaveRan) {
        nativeDetachInterleaveRan = true;
        suppressNativeInitChildRetains = true;
        interleavedInitReturned = invoke_cache_init(
            reinterpret_cast<uintptr_t>(&LegacyWiFi::CacheKernel::routedInit),
            manager, boundController, interface);
        suppressNativeInitChildRetains = false;
        OwnerKey interleavedKey {};
        interleavedInitSawOwner = LegacyWiFi::CacheKernel::owner(
            manager, boundController, interface, classifiedSource, &interleavedKey);
    }
    write64(bytes + InterfaceScanManagerOffset, 0);
    OwnerKey key {};
    detachSawOwnerRetired = !manager || !LegacyWiFi::CacheKernel::owner(
        manager, boundController, interface, expectedSource, &key);
    assert(detachSawOwnerRetired);
    if (manager) {
        assert(objectIsLive(manager));
        if (expectQuiesceBeforeDetach) {
            assert(objectState(boundTimer).quiesced);
            assert(referenceCount(manager) == (leaseHeldForDetach ? 4U : 3U));
            assert(referenceCount(interface) >= (leaseHeldForDetach ? 3U : 2U));
        }
        // Native detach drops the interface's manager reference. A keeper or
        // Lease may keep the manager alive beyond this point.
        releaseObject(manager);
    }
}

#if defined(__APPLE__)
#define C_SYMBOL(name) "_" #name
#else
#define C_SYMBOL(name) #name
#endif
extern "C" uintptr_t invoke_cache_update(uintptr_t entry, void *manager,
                                          void *node, void *request);
extern "C" void cache_update_return_pc();
extern "C" bool invoke_cache_init(uintptr_t entry, void *manager,
                                  void *controller, void *interface);
extern "C" void cache_init_return_pc();
#if defined(__x86_64__)
__asm__(
    ".text\n"
    ".globl " C_SYMBOL(invoke_cache_update) "\n"
    C_SYMBOL(invoke_cache_update) ":\n"
    "mov %rdi, %r11\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "call *%r11\n"
    ".globl " C_SYMBOL(cache_update_return_pc) "\n"
    C_SYMBOL(cache_update_return_pc) ":\n"
    "ret\n"
    ".globl " C_SYMBOL(invoke_cache_init) "\n"
    C_SYMBOL(invoke_cache_init) ":\n"
    "mov %rdi, %r11\n"
    "mov %rsi, %rdi\n"
    "mov %rdx, %rsi\n"
    "mov %rcx, %rdx\n"
    "call *%r11\n"
    ".globl " C_SYMBOL(cache_init_return_pc) "\n"
    C_SYMBOL(cache_init_return_pc) ":\n"
    "ret\n");
#elif defined(__aarch64__) || defined(__arm64__)
__asm__(
    ".text\n"
    ".globl " C_SYMBOL(invoke_cache_update) "\n"
    C_SYMBOL(invoke_cache_update) ":\n"
    "mov x16, x0\n"
    "mov x0, x1\n"
    "mov x1, x2\n"
    "mov x2, x3\n"
    "blr x16\n"
    ".globl " C_SYMBOL(cache_update_return_pc) "\n"
    C_SYMBOL(cache_update_return_pc) ":\n"
    "ret\n"
    ".globl " C_SYMBOL(invoke_cache_init) "\n"
    C_SYMBOL(invoke_cache_init) ":\n"
    "mov x16, x0\n"
    "mov x0, x1\n"
    "mov x1, x2\n"
    "mov x2, x3\n"
    "blr x16\n"
    ".globl " C_SYMBOL(cache_init_return_pc) "\n"
    C_SYMBOL(cache_init_return_pc) ":\n"
    "ret\n");
#else
#error "The cache route harness requires x86_64 or arm64"
#endif

static uintptr_t providerBaseForExactCallsite() {
    const uintptr_t returnPC = reinterpret_cast<uintptr_t>(&cache_update_return_pc);
    assert(returnPC > 0x61ed6);
    return returnPC - 0x61ed6;
}
static bool installAdapter(KernelPatcher *out = nullptr) {
    static KernelPatcher patcher;
    patcher.clearError();
    const LegacyWiFi::CacheKernel::API api = callbacks();
    const bool result = LegacyWiFi::CacheKernel::initialize(
        patcher, 0, providerBaseForExactCallsite(), 0x70000, true, api);
    if (out) *out = patcher;
    return result;
}
static void finishBoundObjects() {
    void *timer = boundTimer;
    void *workLoop = boundWorkLoop;
    void *interface = boundInterface;
    void *controller = boundController;
    boundTimer = boundWorkLoop = boundInterface = boundController = nullptr;
    boundManager = nullptr;
    managerHasKeeper = false;
    if (timer && objectIsLive(timer)) releaseObject(timer);
    if (workLoop && objectIsLive(workLoop)) releaseObject(workLoop);
    if (interface && objectIsLive(interface)) releaseObject(interface);
    if (controller && objectIsLive(controller)) releaseObject(controller);
}
static void initBoundManager(void *manager, bool preexistingHead = false) {
    prepareNativeObjects(manager);
    managerFreed = false;
    initResult = true;
    initWithPreexistingHead = preexistingHead;
    const uintptr_t imageBase = providerBaseForExactCallsite();
    if (!initReturnPcRelocated) {
        assert(LegacyWiFi::CacheKernel::expectedInitReturn == imageBase + 0x57a46);
        // The real provider return PC is pinned above. This test-only callsite
        // is relocated into its contract slot so the wrapper exercises that
        // exact admission guard without synthesizing unrelated function bytes.
        LegacyWiFi::CacheKernel::expectedInitReturn =
            reinterpret_cast<uintptr_t>(&cache_init_return_pc);
        initReturnPcRelocated = true;
    } else {
        assert(LegacyWiFi::CacheKernel::expectedInitReturn ==
               reinterpret_cast<uintptr_t>(&cache_init_return_pc));
    }
    assert(invoke_cache_init(
        reinterpret_cast<uintptr_t>(&LegacyWiFi::CacheKernel::routedInit),
        manager, boundController, boundInterface));
    OwnerKey key {};
    managerHasKeeper = LegacyWiFi::CacheKernel::owner(
        manager, boundController, boundInterface, classifiedSource, &key);
}
static void initWrongCaller(void *manager) {
    prepareNativeObjects(manager);
    initResult = true;
    (void)LegacyWiFi::CacheKernel::routedInit(manager, boundController, boundInterface);
    managerHasKeeper = false;
}
static void issueExactUpdate(void *manager, void *node) {
    expectedSource = classifiedSource;
    (void)invoke_cache_update(
        reinterpret_cast<uintptr_t>(&LegacyWiFi::CacheKernel::routedUpdate),
        manager, node, nullptr);
}
static void cleanupWithProviderFree(void *manager) {
    assert(manager == boundManager && boundInterface);
    expectQuiesceBeforeDetach = managerHasKeeper;
    LegacyWiFi::CacheKernel::routedDetach(boundInterface, 0, nullptr);
    assert(!objectIsLive(manager));
    assert(nativeNodes.empty());
    finishBoundObjects();
}
static void cleanupUninitializedManager(void *manager) {
    releaseObject(manager);
    assert(!objectIsLive(manager));
    assert(nativeNodes.empty());
}

static void scenarioHealthy() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    assert(initCalls == 1);
    assert(read64(static_cast<uint8_t *>(manager) + 0x50) ==
           reinterpret_cast<uintptr_t>(boundController));
    assert(read64(static_cast<uint8_t *>(manager) + 0x58) ==
           reinterpret_cast<uintptr_t>(boundInterface));
    assert(read64(static_cast<uint8_t *>(manager) + 0x10) == 0);
    assert(read64(static_cast<uint8_t *>(manager) + 0x18) == 0);
    OwnerKey key {};
    assert(LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    assert(key.manager == reinterpret_cast<uintptr_t>(manager));
    assert(key.generation != 0);
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned43224, &key));

    auto *node = makeNode(12);
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, node);
    assert(updateSawRegistration && updateCalls == 1);
    checkReleaseRetired = true;
    LegacyWiFi::CacheKernel::routedRelease(node);
    assert(releaseCalls == 1);
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(lastOwner, expectedSource,
                                                     lastTuple));
    cleanupWithProviderFree(manager);
    assert(freeCalls == 1 && freeSawOwnerRetired);
    assert(lockDepth == 0 && interruptsEnabled);
}

static void scenarioZeroIEIgnoredPointer() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    const uintptr_t ignored = reinterpret_cast<uintptr_t>(manager) + 0x40;
    auto *node = makeNode(0, ignored);
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, node);
    assert(updateSawRegistration);
    assert(read64(static_cast<uint8_t *>(node) + CacheNodeIEPointerOffset) == ignored);
    assert(lastTuple.ie == 0 && lastTuple.ieSize == 0);
    checkReleaseRetired = true;
    LegacyWiFi::CacheKernel::routedRelease(node);
    cleanupWithProviderFree(manager);
}

static void scenarioWrongCaller() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    auto *node = makeNode();
    expectRegisteredAtUpdate = false;
    (void)LegacyWiFi::CacheKernel::routedUpdate(manager, node, nullptr);
    assert(updateCalls == 1 && !updateSawRegistration);
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);

    manager = makeManager();
    initWrongCaller(manager); // Native init succeeds, but the return PC is not admitted.
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);
}

static void scenarioUnknownAndPreexisting() {
    assert(installAdapter());
    auto *manager = makeManager();
    auto *unknownNode = makeNode();
    expectedSource = Source::Pinned4331;
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, unknownNode); // No observed successful init: never adopt.
    assert(updateCalls == 1 && !updateSawRegistration);
    cleanupUninitializedManager(manager);

    manager = makeManager();
    initBoundManager(manager, true);
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    auto *oldNode = makeNode();
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, oldNode);
    assert(updateCalls == 2 && !updateSawRegistration);
    cleanupWithProviderFree(manager);
}

static void scenarioDoubleInitAndSourceMismatch() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    OwnerKey oldKey {};
    assert(LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &oldKey));
    auto *first = makeNode();
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, first);
    assert(updateSawRegistration);

    // A second initializer without an intervening free invalidates the prior
    // generation and may not silently bless existing allocations again.
    expectRegisteredAtUpdate = false;
    const unsigned priorInitCalls = initCalls;
    assert(!LegacyWiFi::CacheKernel::routedInit(manager, boundController,
                                                boundInterface));
    assert(initCalls == priorInitCalls);
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &oldKey));
    auto *second = makeNode();
    issueExactUpdate(manager, second);
    assert(updateCalls == 2 && !updateSawRegistration);
    cleanupWithProviderFree(manager);

    classifiedSource = Source::Unknown;
    manager = makeManager();
    initBoundManager(manager);
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &oldKey));
    auto *unsupported = makeNode();
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, unsupported);
    assert(updateCalls == 3);
    cleanupWithProviderFree(manager);
}

static void scenarioReaderAndReferenceFailures() {
    assert(installAdapter());
    auto *manager = makeManager();
    copyCount = 0;
    partialCopyAt = 1;
    initBoundManager(manager); // Partial manager snapshot must not create owner.
    partialCopyAt = 0;
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    auto *withoutOwner = makeNode();
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, withoutOwner);
    assert(updateCalls == 1);
    cleanupWithProviderFree(manager);

    manager = makeManager();
    initValidationAllowed = false;
    initBoundManager(manager);
    initValidationAllowed = true;
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);

    manager = makeManager();
    initBoundManager(manager);
    auto *partialNode = makeNode();
    copyCount = 0;
    partialCopyAt = 1;
    issueExactUpdate(manager, partialNode);
    partialCopyAt = 0;
    assert(updateCalls == 2 && !updateSawRegistration);
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);

    manager = makeManager();
    initBoundManager(manager);
    auto *referencedNode = makeNode();
    write64(static_cast<uint8_t *>(referencedNode) + 0x10, 1);
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, referencedNode);
    assert(updateCalls == 3 && !updateSawRegistration);
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);
}

static void scenarioInterruptContext() {
    assert(installAdapter());
    auto *manager = makeManager();
    interruptContext = true;
    initBoundManager(manager);
    interruptContext = false;
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    auto *node = makeNode();
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, node);
    assert(updateCalls == 1 && !updateSawRegistration);
    cleanupWithProviderFree(manager);

    manager = makeManager();
    initBoundManager(manager);
    auto *disabledNode = makeNode();
    interruptsEnabled = false;
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, disabledNode);
    interruptsEnabled = true;
    assert(updateCalls == 2 && !updateSawRegistration);
    cleanupWithProviderFree(manager);
}

static void scenarioRegistryFull() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    nativeNodes.reserve(1025);
    for (unsigned i = 0; i < 1024; ++i) {
        auto *node = makeNode();
        expectRegisteredAtUpdate = true;
        issueExactUpdate(manager, node);
    }
    assert(updateCalls == 1024 && updateSawRegistration);
    auto *overflow = makeNode();
    expectRegisteredAtUpdate = false;
    issueExactUpdate(manager, overflow);
    assert(updateCalls == 1025);
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);
    assert(releaseCalls == 1025);
}

static void scenarioLeaseAndDetach() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    assert(referenceCount(manager) == 2); // Native reference plus owner keeper.
    assert(referenceCount(boundController) == 2); // Caller plus native manager.
    assert(referenceCount(boundInterface) == 1);
    assert(referenceCount(boundWorkLoop) == 2 && referenceCount(boundTimer) == 2);

    LegacyWiFi::CacheKernel::Lease lease;
    gateHeld = false;
    const unsigned managerBefore = referenceCount(manager);
    assert(!lease.acquire(boundController, boundInterface, Source::Pinned4331));
    assert(referenceCount(manager) == managerBefore);
    gateHeld = true;
    assert(!lease.acquire(boundController, boundInterface, Source::Pinned43224));
    assert(referenceCount(manager) == managerBefore);
    bindingValidationAllowed = false;
    assert(!lease.acquire(boundController, boundInterface, Source::Pinned4331));
    assert(referenceCount(manager) == managerBefore);
    bindingValidationAllowed = true;

    assert(lease.acquire(boundController, boundInterface, Source::Pinned4331));
    assert(lease.current());
    assert(lease.manager() == manager && lease.source() == Source::Pinned4331);
    assert(referenceCount(manager) == 3);
    assert(referenceCount(boundController) == 3);
    assert(referenceCount(boundInterface) == 2);
    assert(managerRetainsInLock >= 1);
    assert(lockDepth == 0);

    auto *managerBytes = static_cast<uint8_t *>(manager);
    const uintptr_t originalController = read64(managerBytes + 0x50);
    write64(managerBytes + 0x50, originalController + 8);
    assert(!lease.current());
    write64(managerBytes + 0x50, originalController);
    const uintptr_t originalInterface = read64(managerBytes + 0x58);
    write64(managerBytes + 0x58, originalInterface + 8);
    assert(!lease.current());
    write64(managerBytes + 0x58, originalInterface);
    const uintptr_t originalLoop = read64(managerBytes + 0x60);
    write64(managerBytes + 0x60, originalLoop + 8);
    assert(!lease.current());
    write64(managerBytes + 0x60, originalLoop);
    const uintptr_t originalSlot = read64(
        static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset);
    write64(static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset,
            originalSlot + 8);
    assert(!lease.current());
    write64(static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset,
            originalSlot);
    assert(lease.current());

    const unsigned validationBeforeDetach = validationCalls;
    expectQuiesceBeforeDetach = true;
    leaseHeldForDetach = true;
    LegacyWiFi::CacheKernel::routedDetach(boundInterface, 0, nullptr);
    leaseHeldForDetach = false;
    assert(detachCalls == 1 && detachSawOwnerRetired);
    assert(quiesceCalls == 1 && validationCalls == validationBeforeDetach);
    assert(!lease.current());
    assert(objectIsLive(manager) && referenceCount(manager) == 1);
    assert(managerRetainsInLock >= 2); // Lease pin and detach's local retirement hold.
    assert(read64(static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset) == 0);
    assert(lockDepth == 0 && interruptsEnabled);

    lease.reset(); // The final Lease manager hold runs the real native free route.
    assert(!objectIsLive(manager) && managerFreed && freeCalls == 1);
    assert(!lease.key().manager && lease.source() == Source::Unknown);
    finishBoundObjects();
    assert(objectStates.empty());
    assert(lockDepth == 0 && interruptsEnabled);
}

static void scenarioBindingMutationAndNoGate() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    LegacyWiFi::CacheKernel::Lease lease;
    assert(lease.acquire(boundController, boundInterface, Source::Pinned4331));
    const uintptr_t originalTimer = read64(static_cast<uint8_t *>(manager) + 0x68);
    write64(static_cast<uint8_t *>(manager) + 0x68, originalTimer + 8);
    assert(!lease.current());
    write64(static_cast<uint8_t *>(manager) + 0x68, originalTimer);
    const uintptr_t originalRetained = read64(static_cast<uint8_t *>(manager) + 0x78);
    write64(static_cast<uint8_t *>(manager) + 0x78, originalRetained + 8);
    assert(!lease.current());
    write64(static_cast<uint8_t *>(manager) + 0x78, originalRetained);
    gateHeld = false;
    assert(!lease.current());
    gateHeld = true;
    assert(lease.current());
    expectQuiesceBeforeDetach = true;
    leaseHeldForDetach = true;
    LegacyWiFi::CacheKernel::routedDetach(boundInterface, 0, nullptr);
    leaseHeldForDetach = false;
    assert(!lease.current());
    assert(objectIsLive(manager));
    lease.reset();
    assert(!objectIsLive(manager));
    finishBoundObjects();
    assert(objectStates.empty());
}

static void scenarioDetachDuringInitValidation() {
    assert(installAdapter());
    auto *manager = makeManager();
    detachDuringValidation = true;
    initBoundManager(manager);
    detachDuringValidation = false;
    assert(validationInterleaveRan && initCalls == 1 && detachCalls == 1);
    assert(!managerHasKeeper && !objectIsLive(manager) && managerFreed);
    assert(read64(static_cast<uint8_t *>(boundInterface) +
                  InterfaceScanManagerOffset) == 0);
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    finishBoundObjects();
    assert(objectStates.empty() && nativeNodes.empty());
}

static void scenarioInitDuringNativeDetachAndUnrelatedEpoch() {
    assert(installAdapter());
    auto *manager = makeManager();
    initValidationAllowed = false; // Native init succeeds; no keeper is published.
    initBoundManager(manager);
    initValidationAllowed = true;
    assert(!managerHasKeeper && objectIsLive(manager));
    initDuringNativeDetach = true;
    cleanupWithProviderFree(manager);
    initDuringNativeDetach = false;
    assert(nativeDetachInterleaveRan && interleavedInitReturned);
    assert(!interleavedInitSawOwner && !objectIsLive(manager) && managerFreed);
    assert(initCalls == 2 && detachCalls == 1);
    assert(objectStates.empty() && nativeNodes.empty());

    // An unrelated detach during admission advances the global epoch and
    // rejects only that in-flight keeper. A later fresh manager is admitted.
    manager = makeManager();
    unrelatedDetachDuringValidation = true;
    initBoundManager(manager);
    unrelatedDetachDuringValidation = false;
    assert(validationInterleaveRan && !managerHasKeeper && objectIsLive(manager));
    OwnerKey key {};
    assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);
    manager = makeManager();
    initBoundManager(manager);
    assert(managerHasKeeper);
    assert(LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &key));
    cleanupWithProviderFree(manager);
    assert(objectStates.empty() && nativeNodes.empty());
}

static void issueCacheNode(void *manager, void *node, uint32_t references) {
    populateCacheOnUpdate = true;
    updateNodeReferenceCount = references;
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, node);
}

static void scenarioSelectiveCachePrune(Source source) {
    classifiedSource = source;
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    auto *requestNode = makeNode();
    setNodeIdentity(requestNode, "home", 1, false);
    issueCacheNode(manager, requestNode, 3);
    auto *secureNode = makeNode(3);
    setNodeIdentity(secureNode, "home", 1, true);
    issueCacheNode(manager, secureNode, 1);
    const uintptr_t secureIE = read64(static_cast<uint8_t *>(secureNode) +
                                      CacheNodeIEPointerOffset);
    const Tuple secureTuple = tupleFor(secureNode);
    auto *survivor = makeNode();
    setNodeIdentity(survivor, "guest", 1, false);
    issueCacheNode(manager, survivor, 1);
    populateCacheOnUpdate = false;
    assert(updateCalls == 3 && nativeNodes.size() == 3);

    LegacyWiFi::CacheKernel::Lease lease;
    assert(lease.acquire(boundController, boundInterface, source));
    const auto key = networkKey("home", 9, 3); // open or RSN; AP mode wildcard.
    LegacyWiFi::SelectiveCache::Entry scratch[3] {};
    LegacyWiFi::SelectiveCache::Result result {9, 9, 9, 9};
    const auto original = captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {requestNode, CacheNodeSize},
        {secureNode, CacheNodeSize}, {survivor, CacheNodeSize}});
    const auto tooSmall = LegacyWiFi::CacheKernel::prune(
        lease, key, scratch, 2, &result);
    assert(tooSmall == LegacyWiFi::SelectiveCache::Status::CapacityExceeded);
    assert(result.examinedNodes == 0 && result.matchedNodes == 0 &&
           result.retainedForRequests == 0 && result.destroyedNodes == 0);
    assert(captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {requestNode, CacheNodeSize},
        {secureNode, CacheNodeSize}, {survivor, CacheNodeSize}}) == original);
    assert(releaseCalls == 0 && freedIECalls == 0);
    result = {9, 9, 9, 9};
    const auto oversized = LegacyWiFi::CacheKernel::prune(
        lease, key, scratch, 1025, &result);
    assert(oversized == LegacyWiFi::SelectiveCache::Status::CapacityExceeded);
    assert(result.examinedNodes == 0 && result.matchedNodes == 0 &&
           result.retainedForRequests == 0 && result.destroyedNodes == 0);
    assert(captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {requestNode, CacheNodeSize},
        {secureNode, CacheNodeSize}, {survivor, CacheNodeSize}}) == original);
    assert(releaseCalls == 0 && freedIECalls == 0);

    pruneExpectedHead = reinterpret_cast<uintptr_t>(survivor);
    pruneExpectedDetachedNode = reinterpret_cast<uintptr_t>(secureNode);
    pruneExpectedRetainedNode = reinterpret_cast<uintptr_t>(requestNode);
    checkPruneDestroyState = true;
    const auto status = LegacyWiFi::CacheKernel::prune(
        lease, key, scratch, 3, &result);
    checkPruneDestroyState = false;
    assert(status == LegacyWiFi::SelectiveCache::Status::Ok);
    assert(result.examinedNodes == 3 && result.matchedNodes == 2 &&
           result.retainedForRequests == 1 && result.destroyedNodes == 1);
    assert(read64(static_cast<uint8_t *>(manager) + ManagerCacheHeadOffset) ==
           reinterpret_cast<uintptr_t>(survivor));
    assert(read64(static_cast<uint8_t *>(survivor) + 8) ==
           reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(manager) +
                                       ManagerCacheHeadOffset));
    assert(read64(static_cast<uint8_t *>(survivor)) == 0);
    assert(read64(static_cast<uint8_t *>(requestNode)) == 0 &&
           read64(static_cast<uint8_t *>(requestNode) + 8) == 0);
    assert(LegacyWiFi::ScanBridge::read32(static_cast<uint8_t *>(requestNode) + 0x10) == 2);
    assert(releaseCalls == 1 && freedIECalls == 1);
    assert(liveIEPointers.count(secureIE) == 0);
    const Tuple requestTuple = tupleFor(requestNode);
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(
        lease.key(), lease.source(), secureTuple));

    // The two request wrappers retain their detached node independently of
    // manager membership. Its allocation is destroyed only after both drop.
    write32(static_cast<uint8_t *>(requestNode) + 0x10, 1);
    assert(objectIsLive(manager));
    write32(static_cast<uint8_t *>(requestNode) + 0x10, 0);
    LegacyWiFi::CacheKernel::routedRelease(requestNode);
    assert(releaseCalls == 2 && nativeNodes.size() == 1);
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(
        lease.key(), lease.source(), requestTuple));
    lease.reset();
    cleanupWithProviderFree(manager);
    assert(objectStates.empty() && nativeNodes.empty() && liveIEPointers.empty());
}

static void scenarioPruneRejectsUnknownAllocation() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    auto *known = makeNode();
    setNodeIdentity(known, "home", 1, false);
    issueCacheNode(manager, known, 1);
    populateCacheOnUpdate = false;
    auto *unknown = makeNode();
    setNodeIdentity(unknown, "home", 1, false);
    write32(static_cast<uint8_t *>(unknown) + 0x10, 1);
    const uintptr_t headSlot = reinterpret_cast<uintptr_t>(static_cast<uint8_t *>(manager) +
        ManagerCacheHeadOffset);
    write64(unknown, reinterpret_cast<uintptr_t>(known));
    write64(static_cast<uint8_t *>(unknown) + 8, headSlot);
    write64(static_cast<uint8_t *>(known) + 8,
            reinterpret_cast<uintptr_t>(unknown));
    write64(reinterpret_cast<void *>(headSlot), reinterpret_cast<uintptr_t>(unknown));

    LegacyWiFi::CacheKernel::Lease lease;
    assert(lease.acquire(boundController, boundInterface, Source::Pinned4331));
    const auto before = captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {known, CacheNodeSize}, {unknown, CacheNodeSize}});
    LegacyWiFi::SelectiveCache::Entry scratch[4] {};
    LegacyWiFi::SelectiveCache::Result result {7, 7, 7, 7};
    const auto status = LegacyWiFi::CacheKernel::prune(
        lease, networkKey("home", 1, 3), scratch, 4, &result);
    assert(status == LegacyWiFi::SelectiveCache::Status::AccessFailure);
    assert(result.examinedNodes == 0 && result.matchedNodes == 0 &&
           result.retainedForRequests == 0 && result.destroyedNodes == 0);
    assert(captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {known, CacheNodeSize}, {unknown, CacheNodeSize}}) == before);
    assert(releaseCalls == 0 && freedIECalls == 0);

    // Restore the verified provider list, then release the unregistered test
    // allocation through the native destructor path.
    write64(reinterpret_cast<void *>(headSlot), reinterpret_cast<uintptr_t>(known));
    write64(static_cast<uint8_t *>(known) + 8, headSlot);
    LegacyWiFi::CacheKernel::routedRelease(unknown);
    assert(unknownReleaseCalls == 1 && releaseCalls == 1);
    lease.reset();
    cleanupWithProviderFree(manager);
    assert(objectStates.empty() && nativeNodes.empty() && liveIEPointers.empty());
}

static void scenarioPruneRejectsChangedOrRevokedLease() {
    assert(installAdapter());
    auto *manager = makeManager();
    initBoundManager(manager);
    auto *node = makeNode();
    setNodeIdentity(node, "home", 1, false);
    issueCacheNode(manager, node, 1);
    populateCacheOnUpdate = false;
    LegacyWiFi::CacheKernel::Lease lease;
    assert(lease.acquire(boundController, boundInterface, Source::Pinned4331));
    LegacyWiFi::SelectiveCache::Entry scratch[2] {};
    LegacyWiFi::SelectiveCache::Result result {7, 7, 7, 7};
    const auto key = networkKey("home", 1, 3);

    const uintptr_t originalSlot = read64(static_cast<uint8_t *>(boundInterface) +
                                          InterfaceScanManagerOffset);
    write64(static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset, 0);
    const auto changedSlotSnapshot = captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {node, CacheNodeSize}});
    auto status = LegacyWiFi::CacheKernel::prune(lease, key, scratch, 2, &result);
    assert(status == LegacyWiFi::SelectiveCache::Status::AccessFailure);
    assert(result.examinedNodes == 0 && result.matchedNodes == 0 &&
           result.retainedForRequests == 0 && result.destroyedNodes == 0);
    assert(captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {node, CacheNodeSize}}) == changedSlotSnapshot);
    assert(releaseCalls == 0 && objectIsLive(manager));
    write64(static_cast<uint8_t *>(boundInterface) + InterfaceScanManagerOffset,
            originalSlot);

    expectQuiesceBeforeDetach = true;
    leaseHeldForDetach = true;
    LegacyWiFi::CacheKernel::routedDetach(boundInterface, 0, nullptr);
    leaseHeldForDetach = false;
    expectQuiesceBeforeDetach = false;
    const auto revokedSnapshot = captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {node, CacheNodeSize}});
    result = {7, 7, 7, 7};
    status = LegacyWiFi::CacheKernel::prune(lease, key, scratch, 2, &result);
    assert(status == LegacyWiFi::SelectiveCache::Status::AccessFailure);
    assert(result.examinedNodes == 0 && result.matchedNodes == 0 &&
           result.retainedForRequests == 0 && result.destroyedNodes == 0);
    assert(captureRegions({{manager, ScanManagerInstanceSize},
        {boundInterface, 0x300}, {node, CacheNodeSize}}) == revokedSnapshot);
    assert(releaseCalls == 0 && objectIsLive(manager));
    lease.reset();
    assert(!objectIsLive(manager) && managerFreed);
    finishBoundObjects();
    assert(objectStates.empty() && nativeNodes.empty() && liveIEPointers.empty());
}

static void scenarioSameAddressNewGeneration() {
    assert(installAdapter());
    quarantineManagerOnFree = true;
    auto *manager = makeManager();
    initBoundManager(manager);
    OwnerKey oldKey {};
    assert(LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &oldKey));
    auto *oldNode = makeNode(8);
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, oldNode);
    const Tuple oldTuple = lastTuple;
    const uintptr_t sameAddress = reinterpret_cast<uintptr_t>(manager);
    cleanupWithProviderFree(manager);
    assert(freeSawOwnerRetired && nativeNodes.empty() && !objectIsLive(manager));
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(oldKey, Source::Pinned4331,
                                                     oldTuple));

    // Reuse the quarantined allocator block only after the native free route
    // ran and removed the old generation.
    reuseQuarantinedManager = true;
    manager = makeManager();
    assert(reinterpret_cast<uintptr_t>(manager) == sameAddress);
    initBoundManager(manager);
    OwnerKey newKey {};
    assert(LegacyWiFi::CacheKernel::owner(manager, boundController,
        boundInterface, Source::Pinned4331, &newKey));
    assert(newKey.manager == sameAddress);
    assert(newKey.generation != oldKey.generation);
    auto *newNode = makeNode(4);
    expectRegisteredAtUpdate = true;
    issueExactUpdate(manager, newNode);
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(oldKey, Source::Pinned4331,
                                                     oldTuple));
    assert(LegacyWiFi::CacheKernel::ownsAllocations(newKey, Source::Pinned4331,
                                                    lastTuple));
    cleanupWithProviderFree(manager);
    assert(managerFreed && nativeNodes.empty());
    assert(!LegacyWiFi::CacheKernel::ownsAllocations(oldKey, Source::Pinned4331,
                                                     oldTuple));
    for (void *block : managerQuarantine) std::free(block);
    managerQuarantine.clear();
    quarantineManagerOnFree = false;
}

static void scenarioNotVerified() {
    KernelPatcher patcher;
    const LegacyWiFi::CacheKernel::API missingCallbacks {};
    assert(!LegacyWiFi::CacheKernel::initialize(
        patcher, 0, providerBaseForExactCallsite(), 0x70000, true, missingCallbacks));
    assert(patcher.routeCalls == 0);
    assert(!LegacyWiFi::CacheKernel::ready());
    const LegacyWiFi::CacheKernel::API api = callbacks();
    assert(!LegacyWiFi::CacheKernel::initialize(
        patcher, 0, providerBaseForExactCallsite(), 0x70000, false, api));
    assert(patcher.routeCalls == 0 && !LegacyWiFi::CacheKernel::ready());
    // Preconditions rejected before routing do not consume the one attempt.
    assert(LegacyWiFi::CacheKernel::initialize(
        patcher, 0, providerBaseForExactCallsite(), 0x70000, true, api));
    assert(patcher.routeCalls == 5 && LegacyWiFi::CacheKernel::ready());
}

static void scenarioPartialRoute(unsigned failedRoute) {
    KernelPatcher patcher;
    patcher.failRouteCall = failedRoute;
    const LegacyWiFi::CacheKernel::API api = callbacks();
    assert(!LegacyWiFi::CacheKernel::initialize(
        patcher, 0, providerBaseForExactCallsite(), 0x70000, true, api));
    assert(patcher.routeCalls == failedRoute);
    assert(!LegacyWiFi::CacheKernel::ready());

    // The fake patcher wrote each original trampoline before the selected
    // failure. Directly invoke every resident wrapper and prove it continues
    // into the corresponding native callback without registering ownership.
    assert(LegacyWiFi::CacheKernel::originalFree != nullptr);
    auto *manager = makeManager();
    if (failedRoute >= 5) {
        assert(LegacyWiFi::CacheKernel::originalInit != nullptr);
        initBoundManager(manager);
        OwnerKey key {};
        assert(!LegacyWiFi::CacheKernel::owner(manager, boundController,
            boundInterface, Source::Pinned4331, &key));
    }
    if (failedRoute >= 4) {
        assert(LegacyWiFi::CacheKernel::originalUpdate != nullptr);
        auto *node = makeNode(8);
        expectRegisteredAtUpdate = false;
        issueExactUpdate(manager, node);
        assert(!updateSawRegistration);
    }
    if (failedRoute >= 2) {
        assert(LegacyWiFi::CacheKernel::originalRelease != nullptr);
        auto *node = makeNode();
        LegacyWiFi::CacheKernel::routedRelease(node);
    }
    if (failedRoute >= 3) {
        assert(LegacyWiFi::CacheKernel::originalDetach != nullptr);
        void *interface = makeObject(0x300, ObjectKind::Interface);
        LegacyWiFi::CacheKernel::routedDetach(interface, 0, nullptr);
        releaseObject(interface);
    }
    if (failedRoute >= 5) cleanupWithProviderFree(manager);
    else releaseObject(manager);
    assert(freeCalls >= 1 && freeSawOwnerRetired && managerFreed);
    if (failedRoute >= 4) assert(updateCalls == 1 && !updateSawRegistration);
    assert(nativeNodes.empty());
    assert(lockDepth == 0 && interruptsEnabled);

    // A second initialize attempt is refused and cannot turn on observation,
    // even though the previously published native trampolines remain valid.
    KernelPatcher retry;
    const unsigned previousRouteCalls = patcher.routeCalls;
    assert(!LegacyWiFi::CacheKernel::initialize(
        retry, 0, providerBaseForExactCallsite(), 0x70000, true, api));
    assert(retry.routeCalls == 0 && patcher.routeCalls == previousRouteCalls);
    assert(!LegacyWiFi::CacheKernel::ready());
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const std::string mode(argv[1]);
    if (mode == "healthy") scenarioHealthy();
    else if (mode == "zero_ie") scenarioZeroIEIgnoredPointer();
    else if (mode == "wrong_caller") scenarioWrongCaller();
    else if (mode == "unknown_preexisting") scenarioUnknownAndPreexisting();
    else if (mode == "repeat_source") scenarioDoubleInitAndSourceMismatch();
    else if (mode == "reader_reference") scenarioReaderAndReferenceFailures();
    else if (mode == "irq") scenarioInterruptContext();
    else if (mode == "registry_full") scenarioRegistryFull();
    else if (mode == "lease_detach") scenarioLeaseAndDetach();
    else if (mode == "binding_mutation") scenarioBindingMutationAndNoGate();
    else if (mode == "detach_init_validation") scenarioDetachDuringInitValidation();
    else if (mode == "init_detach_epoch") scenarioInitDuringNativeDetachAndUnrelatedEpoch();
    else if (mode == "cache_prune") scenarioSelectiveCachePrune(Source::Pinned4331);
    else if (mode == "cache_prune_43224") scenarioSelectiveCachePrune(Source::Pinned43224);
    else if (mode == "cache_prune_unknown") scenarioPruneRejectsUnknownAllocation();
    else if (mode == "cache_prune_stale") scenarioPruneRejectsChangedOrRevokedLease();
    else if (mode == "generation") scenarioSameAddressNewGeneration();
    else if (mode == "unverified") scenarioNotVerified();
    else if (mode.size() == 9 && mode.rfind("partial_", 0) == 0)
        scenarioPartialRoute(static_cast<unsigned>(mode.back() - '0'));
    else assert(false && "unknown scenario");
    assert(lockDepth == 0 && interruptsEnabled);
    assert(nativeNodes.empty());
    assert(objectStates.empty());
    assert(liveIEPointers.empty());
    std::puts("production cache-kernel route scenario passed");
    return 0;
}
'''


class LegacyCacheKernelRouteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("xcrun")
        if compiler:
            compiler = [compiler, "clang++"]
        else:
            clang = shutil.which("clang++")
            if not clang:
                raise unittest.SkipTest("clang++ is required for the production-source harness")
            compiler = [clang]
        cls.work = tempfile.TemporaryDirectory(prefix="legacy-cache-kernel-route-")
        root = Path(cls.work.name)
        stubs = root / "stubs"
        (stubs / "Headers").mkdir(parents=True)
        (stubs / "IOKit").mkdir()
        (stubs / "machine").mkdir()
        (stubs / "Headers/kern_patcher.hpp").write_text(KERNEL_PATCHER_STUB)
        (stubs / "IOKit/IOLocks.h").write_text(IOLOCKS_STUB)
        (stubs / "machine/machine_routines.h").write_text(MACHINE_ROUTINES_STUB)
        cpp = root / "cache_kernel_harness.cpp"
        cpp.write_text(HARNESS)
        cls.binary = root / "cache_kernel_harness"
        built = subprocess.run(
            compiler + [
                "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                "-I", str(stubs), "-I", str(PROJECT), str(cpp), "-o", str(cls.binary),
            ], capture_output=True, text=True, timeout=60,
        )
        if built.returncode:
            cls.work.cleanup()
            raise AssertionError(built.stderr)

    @classmethod
    def tearDownClass(cls):
        cls.work.cleanup()

    def scenario(self, mode):
        result = subprocess.run([str(self.binary), mode], capture_output=True,
                                 text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("production cache-kernel route scenario passed", result.stdout)

    def test_init_precedes_registration_and_native_callbacks_are_unlocked(self):
        self.scenario("healthy")

    def test_zero_length_ie_ignores_raw_pointer_without_rewriting_node(self):
        self.scenario("zero_ie")

    def test_wrong_caller_still_reaches_native_update_but_invalidates_owner(self):
        self.scenario("wrong_caller")

    def test_unobserved_or_preexisting_manager_is_never_adopted(self):
        self.scenario("unknown_preexisting")

    def test_repeated_init_and_unsupported_source_fail_closed(self):
        self.scenario("repeat_source")

    def test_partial_reader_and_nonzero_reference_fail_closed(self):
        self.scenario("reader_reference")

    def test_interrupt_and_interrupts_disabled_paths_preserve_native_call(self):
        self.scenario("irq")

    def test_registry_full_invalidates_proof_but_keeps_native_path(self):
        self.scenario("registry_full")

    def test_lease_retains_manager_and_detach_revokes_before_native_release(self):
        self.scenario("lease_detach")

    def test_lease_rechecks_binding_metadata_and_workloop_gate(self):
        self.scenario("binding_mutation")

    def test_detach_during_post_init_validation_keeps_preholds_until_rejection(self):
        self.scenario("detach_init_validation")

    def test_init_during_detach_and_unrelated_epoch_fail_closed(self):
        self.scenario("init_detach_epoch")

    def test_production_prune_mixes_matches_preserves_requests_and_frees_ie(self):
        for mode in ("cache_prune", "cache_prune_43224"):
            with self.subTest(mode=mode):
                self.scenario(mode)

    def test_production_prune_rejects_unregistered_node_without_writes(self):
        self.scenario("cache_prune_unknown")

    def test_production_prune_rejects_changed_or_revoked_lease_without_writes(self):
        self.scenario("cache_prune_stale")

    def test_free_then_same_address_new_generation_rejects_stale_key(self):
        self.scenario("generation")

    def test_rejected_preconditions_do_not_consume_install_attempt(self):
        self.scenario("unverified")

    def test_each_partial_route_preserves_installed_native_trampolines(self):
        for failed_route in range(1, 6):
            with self.subTest(failed_route=failed_route):
                self.scenario(f"partial_{failed_route}")


if __name__ == "__main__":
    unittest.main()
