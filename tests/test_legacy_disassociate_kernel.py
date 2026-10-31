"""Sanitizer-backed SET22 disconnect observation tests over the production adapter."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]

MOCK_HEADERS = r'''
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
using mach_vm_address_t = uint64_t;

uintptr_t disassociateOriginalForSymbol(const char *symbol);
bool disassociateChildActive(unsigned child);
void disassociateRouteBecameResident(const char *symbol);

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
    static constexpr size_t KernelID = 0;
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
        if (disassociateChildActive(0) || disassociateChildActive(1))
            std::abort();
        const uintptr_t original = disassociateOriginalForSymbol(request->symbol);
        if (!original) {
            error = Error::RouteFailure;
            return false;
        }
        disassociateRouteBecameResident(request->symbol);
        std::memcpy(request->originalSlot, &original, sizeof(original));
        uintptr_t storedOriginal = 0;
        std::memcpy(&storedOriginal, request->originalSlot, sizeof(storedOriginal));
        if (storedOriginal != original || !request->target ||
            disassociateChildActive(0) || disassociateChildActive(1))
            std::abort();
        // The test models a detour that has reached memory before a late route
        // error. The already resident wrapper must still call its trampoline.
        if (failRouteCall && routeCalls == failRouteCall) {
            error = Error::RouteFailure;
            return false;
        }
        error = Error::NoError;
        return true;
    }
    Error getError() const { return error; }
    void clearError() { error = Error::NoError; }
    uintptr_t solveSymbol(size_t, const char *) { return 0; }
    uintptr_t solveSymbol(size_t, const char *, uintptr_t, size_t, bool = false) { return 0; }
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
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "legacy_wifi_compat/disassociate_kernel.cpp"

namespace DK = LegacyWiFi::DisassociateKernel;
namespace D = LegacyWiFi::DisassociateChildContract;
namespace A = LegacyWiFi::DisassociateAdmission;
namespace B = LegacyWiFi::CurrentBSS;
namespace C = LegacyWiFi::CacheKernel;
namespace BC = LegacyWiFi::BSSCapture;
namespace N = LegacyWiFi::NetworkIdentity;
namespace M = LegacyWiFi::NetworkMatch;
namespace SB = LegacyWiFi::ScanBridge;

using NativeSetter = int (*)(void *, void *);
using NativeDisable = int32_t (*)(void *, void *);
using NativeWorker = int32_t (*)(void *, uint32_t, void *, void *);
using NativeFindCFG = void *(*)(void *, void *);
using NativeBSSInit4331 = void (*)(void *, void *, void *, void *, uint32_t, uint32_t);
using NativeBSSInit43224 = void (*)(void *, void *, void *, uint32_t);
using NativeRecvParser = int32_t (*)(void *, void *, const void *, uint32_t,
                                     const void *, uint32_t, void *);
using NativeJoinComplete4331 = void (*)(void *, void *, void *, const void *, uint32_t);
using NativeJoinComplete43224 = void (*)(void *, const void *, uint32_t);
using NativeClearBSSID = uintptr_t (*)(void *);
using NativeCfgMfree = void (*)(void *, void *);
using NativeStateChange = int32_t (*)(void *);

enum class Mutator : uint8_t { None, BSSInit, JoinComplete, ClearBSSID, CfgMfree, Down, Detach };
enum class MutationPoint : uint8_t { None, BeforeWorker, InsideWorker };

static IOSimpleLock fakeLock {1};
static unsigned lockDepth = 0;
static bool interruptsEnabled = true;
static bool interruptContext = false;

struct Region { uintptr_t start; size_t size; bool live; };
static std::vector<Region> regions;
static std::vector<void *> allocations;
static unsigned invalidReads = 0;
static unsigned readsFromFreedRegions = 0;
static unsigned scratchAllocations = 0;
static unsigned scratchDeallocations = 0;
static bool failScratchAllocation = false;
static bool scratchWasZeroed = false;

struct Behavior {
    D::ChildKind child = D::Brcm4331;
    N::Source source = N::Source::Pinned4331;
    bool classifyOtherChild = false;
    bool exposeEnhancedReasonConfiguration = false;
    bool enhancedReasonConfigurationKnown = false;
    bool enhancedReasonEnabled = false;
    bool leaseAcquireAllowed = true;
    bool failAllocation = false;
    bool callHelperLookup = false;
    bool wrongFindCFGCaller = false;
    bool callNestedPerform = false;
    bool duplicateSetter = false;
    bool wrongThreadAtSetter = false;
    bool wrongInterfaceAtSetter = false;
    bool wrongDisableCaller = false;
    bool wrongCFG = false;
    bool alternateCurrentBSS = false;
    bool simulateNativeIdleSkip = false;
    bool idleAP = false;
    bool idleCFGAP = false;
    bool idleAssociated = false;
    bool idleSTAAssociated = false;
    bool idleBadType = false;
    bool idleBadState = false;
    bool idleMissingContext = false;
    bool idleSlotMismatch = false;
    bool idleZeroBSSID = false;
    bool idleGateRefusal = false;
    bool idleRevokeAfterSetter = false;
    bool idleEpochChangeAfterSetter = false;
    bool idleStateChangeAfterSetter = false;
    bool idlePointerReplaceAfterSetter = false;
    bool idleIBSSReconfigureNoDown = false;
    uint8_t idleIBSSState = 0;
    bool skipWorker = false;
    bool wrongWorkerCaller = false;
    bool wrongWorkerFlag = false;
    bool wrongWorkerArgument = false;
    bool exerciseSender = false;
    bool wrongSenderCaller = false;
    bool wrongSenderBSSID = false;
    bool wrongSenderThread = false;
    bool failExtendedBuilder = false;
    bool failBodyWrite = false;
    bool failSenderQueue = false;
    bool ccxAssuranceEnabled = false;
    bool ccxAssuranceDisabled = false;
    bool staleFrameOwner = false;
    bool staleBeforeBuilder = false;
    bool staleEpochBeforeBuilder = false;
    bool workerNoClearBSSID = false;
    bool workerNoClearIE = false;
    bool workerResultNonzero = false;
    bool revokeLeaseInWorker = false;
    bool noBeaconBody = false;
    bool headerOnlyBody = false;
    bool shortBeaconBody = false;
    bool malformedIE = false;
    bool oversizedIE = false;
    bool captureRefresh = false;
    bool parserWriteBadCapability = false;
    bool parserWriteNonzeroBody = false;
    int32_t parserNativeResult = 0;
    bool bssInitCopySource = false;
    bool bssInitCorruptTarget = false;
    bool joinCompleteReentry = false;
    bool nestedParserCall = false;
    bool nestedParserDidCall = false;
    Mutator injectedMutator = Mutator::None;
    MutationPoint mutationPoint = MutationPoint::None;
    bool clearWrongCFG = false;
    bool clearWrongPC = false;
    bool clearWrongThread = false;
    bool clearAlternateCallsite = false;
    int setterResult = 0;
    int32_t disableResult = 0;
    int32_t workerResult = 0;
    int handlerResult = 0;
    LegacyWiFi::SelectiveCache::Status pruneStatus =
        LegacyWiFi::SelectiveCache::Status::Ok;
};
static Behavior behavior;

static constexpr uintptr_t ThreadOne = 0x1111;
static constexpr uintptr_t ThreadTwo = 0x2222;
static uintptr_t activeThread = ThreadOne;
static bool leaseCurrent = true;
static unsigned leasesHeld = 0;
static unsigned leaseAcquisitions = 0;
static unsigned enhancedReasonConfigurationCalls = 0;
static uintptr_t fakeManager = 0x1000;
static void *controller = nullptr;
static void *interfaceObject = nullptr;
static void *wlc = nullptr;
static void *wlcif = nullptr;
static void *cfg4331 = nullptr;
static void *cfg43224 = nullptr;
static void *alternateCFG = nullptr;
static void *assocContext4331 = nullptr;
static void *record = nullptr;
static void *ieAllocation = nullptr;
static size_t ieAllocationSize = 0;
static void *joinInputExpected = nullptr;
static void *joinRXExpected = nullptr;
static const void *joinBodyExpected = nullptr;
static uint32_t joinBodyLengthExpected = 0;
static void *joinNestedSource = nullptr;
static int joinPerformBefore = 0;
static int joinPerformAfterNested = 0;
static int joinPerformAfterFree = 0;
static int joinPerformAfterReplacement = 0;
static void *oslHandle = nullptr;
static std::vector<uint8_t> imageBytes;
struct MockPacket {
    uint8_t data[64] {};
    size_t bodyLength = 0;
    bool queued = false;
    bool freed = false;
};
static MockPacket mockPackets[64];
static size_t mockPacketCount = 0;
static bool senderRouteResident = false;
static bool builderRouteResident = false;
static unsigned senderCalls = 0;
static unsigned builderCalls = 0;
static unsigned pktFreeCalls = 0;
static unsigned mbufDataCalls = 0;
static unsigned frameBodyWrites = 0;
static unsigned frameBodyOutReads = 0;
static unsigned frameExtendedBuilderCalls = 0;
static unsigned frameFallbackBuilderCalls = 0;
static unsigned framePacketsQueued = 0;
static unsigned frameQueueFailures = 0;
static uintptr_t activeBodyOutSlot = 0;
static void *lastNativeSenderPacket = nullptr;
static unsigned setterCalls = 0;
static unsigned findCalls = 0;
static unsigned disableCalls = 0;
static unsigned workerCalls = 0;
static unsigned outerCalls = 0;
static unsigned pruneCalls = 0;
static unsigned bssInitCalls = 0;
static unsigned recvParserCalls = 0;
static unsigned joinCompleteCalls = 0;
static unsigned clearBSSIDCalls = 0;
static unsigned cfgMfreeCalls = 0;
static unsigned downCalls = 0;
static unsigned detachCalls = 0;
static unsigned cfgFreeCalls = 0;
static unsigned wlcStopCalls = 0;
static unsigned injectedIEFrees = 0;
static unsigned injectedRecordFrees = 0;
static unsigned injectedCFGFree = 0;
static unsigned injectedWLCFrees = 0;
static bool suppressWorkerWrites = false;
static int observedSetterResult = 0;
static int32_t observedDisableResult = 0;
static int32_t observedWorkerDispatchResult = 0;
static int nestedPerformResult = 0;
static bool partialMode = false;
static int32_t mutatorNativeResult = -31;
static int32_t observedMutatorResult = 0;
static unsigned bssRecordReads = 0;
static unsigned ieAllocationReads = 0;
static unsigned nativeIBSSCalls = 0;
static bool cfgSlotPublished = false;
static bool controllerSlotPublished = false;
static bool cfgSlotWasPublishedAtReentry = false;
static bool controllerSlotWasPublishedAtReentry = false;
static LegacyWiFi::LegacyBridge::Request *lastOriginalRequest = nullptr;

static void *allocateRegion(size_t size) {
    assert(size > 0);
    void *p = std::calloc(1, size);
    assert(p);
    allocations.push_back(p);
    regions.push_back({reinterpret_cast<uintptr_t>(p), size, true});
    return p;
}

static void releaseRegion(void *p) {
    if (!p) return;
    auto it = std::find_if(regions.begin(), regions.end(), [p](const Region &r) {
        return r.start == reinterpret_cast<uintptr_t>(p) && r.live;
    });
    assert(it != regions.end());
    it->live = false;
    auto allocation = std::find(allocations.begin(), allocations.end(), p);
    if (allocation != allocations.end()) allocations.erase(allocation);
    std::free(p);
}

static bool copyFromRegion(uintptr_t address, void *out, size_t size) {
    if (!address || !out || !size || address > UINTPTR_MAX - size) {
        ++invalidReads;
        return false;
    }
    if (record) {
        const uintptr_t begin = reinterpret_cast<uintptr_t>(record);
        const uintptr_t end = begin + D::currentBSSLayout(behavior.child).recordSize;
        if (address < end && begin < address + size) ++bssRecordReads;
    }
    if (ieAllocation) {
        const uintptr_t begin = reinterpret_cast<uintptr_t>(ieAllocation);
        const uintptr_t end = begin + ieAllocationSize;
        if (address < end && begin < address + size) ++ieAllocationReads;
    }
    for (const Region &region : regions) {
        if (address < region.start || address - region.start > region.size ||
            size > region.size - static_cast<size_t>(address - region.start)) continue;
        if (!region.live) {
            ++readsFromFreedRegions;
            return false;
        }
        if (activeBodyOutSlot && address == activeBodyOutSlot &&
            size == sizeof(uintptr_t)) ++frameBodyOutReads;
        std::memcpy(out, reinterpret_cast<const void *>(address), size);
        return true;
    }
    ++invalidReads;
    return false;
}

static void write16(void *p, uint16_t value) { std::memcpy(p, &value, sizeof(value)); }
static void write32(void *p, uint32_t value) { std::memcpy(p, &value, sizeof(value)); }
static void write64(void *p, uint64_t value) { std::memcpy(p, &value, sizeof(value)); }
static uintptr_t imageBase() { return reinterpret_cast<uintptr_t>(imageBytes.data()); }

static size_t makeRefreshBody(uint8_t *body, bool withCCX = false,
                              bool ccxEnabled = false) {
    assert(body);
    std::memset(body, 0, B::BeaconFixedBodyBytes);
    // Beacon body: timestamp (8), interval (2), capability (2), then IEs.
    write16(body + 10, 0x10);
    body[12] = 48; body[13] = 1; body[14] = 0;
    size_t length = 15;
    if (withCCX) {
        uint8_t *ccx = body + length;
        ccx[0] = 221; ccx[1] = 5;
        ccx[2] = 0x00; ccx[3] = 0x40; ccx[4] = 0x96;
        ccx[5] = 0x0b; ccx[6] = ccxEnabled ? 0x80 : 0;
        length += 7;
    }
    return length;
}

static void writeParserRecord(void *output, const void *bssid,
                              const void *body, uint32_t length) {
    assert(output && bssid && body && length >= B::BeaconFixedBodyBytes);
    auto *bytes = static_cast<uint8_t *>(output);
    std::memset(bytes, 0, B::Record4331Size);
    std::memcpy(bytes, bssid, B::BSSIDSize);
    bytes[B::SSIDLengthOffset] = 3;
    std::memcpy(bytes + B::SSIDOffset, "net", 3);
    uint16_t capability = 0;
    std::memcpy(&capability, static_cast<const uint8_t *>(body) + 10, sizeof(capability));
    write16(bytes + B::Capability4331Offset,
            behavior.parserWriteBadCapability ? static_cast<uint16_t>(capability ^ 1) : capability);
    if (behavior.parserWriteNonzeroBody) {
        write64(bytes + B::IEPointerOffset, reinterpret_cast<uintptr_t>(body));
        write16(bytes + B::IELengthOffset, static_cast<uint16_t>(length));
    }
}

static void writeCall(size_t instruction, size_t target) {
    assert(instruction + 5 <= imageBytes.size() && target < imageBytes.size());
    imageBytes[instruction] = 0xe8;
    const uintptr_t returnPC = imageBase() + instruction + 5;
    const uintptr_t destination = imageBase() + target;
    const int64_t delta = destination >= returnPC
        ? static_cast<int64_t>(destination - returnPC)
        : -static_cast<int64_t>(returnPC - destination);
    assert(delta >= INT32_MIN && delta <= INT32_MAX);
    const int32_t rel = static_cast<int32_t>(delta);
    std::memcpy(imageBytes.data() + instruction + 1, &rel, sizeof(rel));
}

static void addStackRegion(void *address, size_t size) {
    assert(address && size);
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    assert(std::none_of(regions.begin(), regions.end(), [start](const Region &region) {
        return region.start == start && region.live;
    }));
    regions.push_back({start, size, true});
}

static void removeStackRegion(void *address) {
    const uintptr_t start = reinterpret_cast<uintptr_t>(address);
    auto region = std::find_if(regions.begin(), regions.end(), [start](const Region &item) {
        return item.start == start && item.live;
    });
    assert(region != regions.end());
    regions.erase(region);
}

static int nativeSetter(void *, void *);
static int32_t nativeDisable(void *, void *);
static int32_t nativeWorker(void *, uint32_t, void *, void *);
static void *nativeFindCFG(void *, void *);
static void nativeBSSInit4331(void *, void *, void *, void *, uint32_t, uint32_t);
static void nativeBSSInit43224(void *, void *, void *, uint32_t);
static int32_t nativeRecvParser(void *, void *, const void *, uint32_t,
                                const void *, uint32_t, void *);
static void nativeJoinComplete4331(void *, void *, void *, const void *, uint32_t);
static void nativeJoinComplete43224(void *, const void *, uint32_t);
static uintptr_t nativeClearBSSID(void *);
static void nativeCfgMfree(void *, void *);
static int32_t nativeDown43224(void *);
static int32_t nativeDetach4331(void *);
static int32_t nativeDetach43224(void *);
static void nativeCfgFree4331(void *, void *);
static void nativeWlcStop(void *);
static bool nativeEnhancedReasonConfiguration(void *, bool *);
static void *nativeSender4331(void *, void *, const void *, void *, void *, uint32_t);
static void *nativeSender43224(void *, void *, const void *, void *, uint32_t);
static void *nativeBuilder(void *, uint32_t, const void *, const void *, const void *,
                           uint32_t, void **);
static void nativePktFree(void *, void *, int);
static void *nativeMbufData(void *);
static void *invokeNativeSenderFromWorker();
static bool regionIsLive(void *);
static int doPerform(LegacyWiFi::LegacyBridge::Request *, void *, void *, bool,
                     uint32_t, uint32_t);
static uintptr_t originalForSymbol(const char *symbol);

// These definitions satisfy the fake KernelPatcher header's runtime probes.
bool disassociateChildActive(unsigned child) {
    return child < D::ChildCount &&
        __atomic_load_n(&LegacyWiFi::DisassociateKernel::children[child].active,
                        __ATOMIC_ACQUIRE) != 0;
}
uintptr_t disassociateOriginalForSymbol(const char *symbol) {
    return originalForSymbol(symbol);
}
void disassociateRouteBecameResident(const char *symbol) {
    if (!symbol) return;
    const auto &sender = D::Functions[behavior.child][D::Sender];
    const auto &builder = D::Functions[behavior.child][D::Builder];
    if (sender.symbol && std::strcmp(symbol, sender.symbol) == 0)
        senderRouteResident = true;
    if (builder.symbol && std::strcmp(symbol, builder.symbol) == 0)
        builderRouteResident = true;
}

static uintptr_t originalForSymbol(const char *symbol) {
    if (!symbol) return 0;
    for (size_t child = 0; child < D::ChildCount; ++child) {
        for (size_t index = 0; index < D::FunctionCount; ++index) {
            const D::FunctionContract &function = D::Functions[child][index];
            if (!function.symbol || std::strcmp(function.symbol, symbol) != 0) continue;
            switch (index) {
            case D::SetDisassociate: return reinterpret_cast<uintptr_t>(&nativeSetter);
            case D::Worker: return reinterpret_cast<uintptr_t>(&nativeWorker);
            case D::Sender:
                return behavior.child == D::Brcm4331
                    ? reinterpret_cast<uintptr_t>(&nativeSender4331)
                    : reinterpret_cast<uintptr_t>(&nativeSender43224);
            case D::Builder: return reinterpret_cast<uintptr_t>(&nativeBuilder);
            case D::PktFree: return reinterpret_cast<uintptr_t>(&nativePktFree);
            case D::CfgFind: return reinterpret_cast<uintptr_t>(&nativeFindCFG);
            case D::Disable: return reinterpret_cast<uintptr_t>(&nativeDisable);
            case D::BSSInit:
                return behavior.child == D::Brcm4331
                    ? reinterpret_cast<uintptr_t>(&nativeBSSInit4331)
                    : reinterpret_cast<uintptr_t>(&nativeBSSInit43224);
            case D::RecvParser: return reinterpret_cast<uintptr_t>(&nativeRecvParser);
            case D::JoinComplete:
                return behavior.child == D::Brcm4331
                    ? reinterpret_cast<uintptr_t>(&nativeJoinComplete4331)
                    : reinterpret_cast<uintptr_t>(&nativeJoinComplete43224);
            case D::ClearBSSID: return reinterpret_cast<uintptr_t>(&nativeClearBSSID);
            case D::CfgMfree: return reinterpret_cast<uintptr_t>(&nativeCfgMfree);
            case D::Down: return reinterpret_cast<uintptr_t>(&nativeDown43224);
            case D::Detach:
                return behavior.child == D::Brcm4331
                    ? reinterpret_cast<uintptr_t>(&nativeDetach4331)
                    : reinterpret_cast<uintptr_t>(&nativeDetach43224);
            case D::CfgFree: return reinterpret_cast<uintptr_t>(&nativeCfgFree4331);
            case D::WlcStop: return reinterpret_cast<uintptr_t>(&nativeWlcStop);
            default: return 0;
            }
        }
    }
    return 0;
}

static void configureImage(D::ChildKind child) {
    // Small mapped callsite fixture: only the exact calls consumed by the
    // production dispatch guards are represented and every rel32 is real.
    imageBytes.assign(0xc0000, 0);
    if (child == D::Brcm4331) {
        const size_t clearBSSID = D::Functions[0][D::ClearBSSID].start;
        writeCall(0xdac5, 0x5f3b8);
        writeCall(0x332e7, 0x5e0aa);
        writeCall(0x5e1e9, 0xb0b53);
        writeCall(0xb0dc0, 0x4d728);
        writeCall(0xb0e3b, 0x4d728);
        writeCall(0x4d777, 0x4a5f3);
        writeCall(0xb0fd1, clearBSSID);
        writeCall(0xb0a06, clearBSSID);
        writeCall(0x46c7b, D::Functions[0][D::RecvParser].start);
        writeCall(0x46cdb, D::Functions[0][D::BSSInit].start);
    } else {
        writeCall(0x68870, 0x900d5);
        writeCall(0x901e2, 0x67583);
        writeCall(0x6778b, 0x7e44e);
        writeCall(0x7e49f, 0x75582);
    }
}

static A::Admission admissionFor(D::ChildKind child) {
    A::Admission admission;
    admission.ready = true;
    admission.child = child;
    admission.index = 19;
    admission.image = {imageBytes.data(), imageBytes.size(), imageBase()};
    for (size_t i = 0; i < D::FunctionCount; ++i) {
        const D::FunctionContract &function = D::Functions[child][i];
        if (function.symbol) admission.symbols.addresses[i] = imageBase() + function.start;
    }
    admission.symbols.addresses[D::PktFree] = reinterpret_cast<uintptr_t>(&nativePktFree);
    admission.imports.addresses[D::MbufData] = reinterpret_cast<uintptr_t>(&nativeMbufData);
    return admission;
}

static void initChildModule(D::ChildKind child, unsigned failRoute = 0) {
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    configureImage(child);
    senderRouteResident = false;
    builderRouteResident = false;
    const DK::API callbacks {
        [](void *, void *) -> N::Source {
            assert(lockDepth == 0);
            if (behavior.classifyOtherChild)
                return behavior.source == N::Source::Pinned4331
                    ? N::Source::Pinned43224 : N::Source::Pinned4331;
            return behavior.source;
        },
        []() -> uintptr_t { assert(lockDepth == 0); return activeThread; },
        [](size_t size) -> void * {
            assert(lockDepth == 0);
            if (behavior.failAllocation || failScratchAllocation) return nullptr;
            ++scratchAllocations;
            return allocateRegion(size);
        },
        [](void *p, size_t size) {
            assert(lockDepth == 0 && p && size);
            auto *bytes = static_cast<uint8_t *>(p);
            scratchWasZeroed = std::all_of(bytes, bytes + size,
                                            [](uint8_t b) { return b == 0; });
            ++scratchDeallocations;
            releaseRegion(p);
        },
        behavior.exposeEnhancedReasonConfiguration
            ? &nativeEnhancedReasonConfiguration : nullptr
    };
    assert(DK::initialize(callbacks));
    KernelPatcher patcher;
    patcher.failRouteCall = failRoute;
    const A::Admission admission = admissionFor(child);
    const bool installed = DK::installChild(patcher, admission);
    const unsigned expectedRouteCalls = child == D::Brcm4331 ? 14 : 10;
    assert(patcher.routeCalls == (failRoute ? failRoute : expectedRouteCalls));
    if (!failRoute) assert(installed && DK::ready(behavior.source));
    else assert(!installed && !DK::ready(behavior.source));
}

namespace ScanKernelIdentity {
bool copyOwnedWiredMemory(uintptr_t address, void *destination, size_t size) {
    assert(lockDepth == 1 && !interruptsEnabled && !interruptContext);
    assert(size <= MaxOwnedWiredRead);
    return copyFromRegion(address, destination, size);
}
}

IOSimpleLock *IOSimpleLockAlloc() { return &fakeLock; }
IOInterruptState IOSimpleLockLockDisableInterrupt(IOSimpleLock *lock) {
    assert(lock == &fakeLock && lockDepth == 0);
    const IOInterruptState old = interruptsEnabled ? 1 : 0;
    interruptsEnabled = false;
    ++lockDepth;
    return old;
}
void IOSimpleLockUnlockEnableInterrupt(IOSimpleLock *lock, IOInterruptState old) {
    assert(lock == &fakeLock && lockDepth == 1);
    --lockDepth;
    interruptsEnabled = old != 0;
}
bool ml_at_interrupt_context() { return interruptContext; }
bool ml_get_interrupts_enabled() { return interruptsEnabled; }

static bool nativeEnhancedReasonConfiguration(void *passedController, bool *enabled) {
    assert(lockDepth == 0 && passedController == controller && enabled);
    ++enhancedReasonConfigurationCalls;
    if (!behavior.enhancedReasonConfigurationKnown) return false;
    *enabled = behavior.enhancedReasonEnabled;
    return true;
}

namespace LegacyWiFi { namespace CacheKernel {
bool Lease::acquire(void *c, void *i, Source s) {
    assert(lockDepth == 0);
    if (!behavior.leaseAcquireAllowed || c != ::controller || i != interfaceObject ||
        s != behavior.source) return false;
    heldKey.manager = fakeManager;
    heldKey.generation = 7;
    heldSource = s;
    controller = c;
    interface = i;
    workLoop = nullptr;
    timer = nullptr;
    ++leasesHeld;
    ++leaseAcquisitions;
    leaseCurrent = true;
    return true;
}
bool Lease::current() const {
    assert(lockDepth == 0);
    return heldKey.manager && heldKey.generation && leaseCurrent;
}
void Lease::reset() {
    assert(lockDepth == 0);
    if (heldKey.manager) {
        assert(leasesHeld > 0);
        --leasesHeld;
    }
    heldKey = {};
    heldSource = Source::Unknown;
    controller = interface = workLoop = timer = nullptr;
}
Lease::~Lease() { reset(); }

static bool identitySeen = false;
static M::Identity lastIdentity {};
SelectiveCache::Status prune(Lease &lease, const M::Identity &identity,
                             SelectiveCache::Entry *scratch, size_t capacity,
                             SelectiveCache::Result *result) {
    assert(lockDepth == 0 && lease.current() && scratch && capacity == MaximumPruneNodes && result);
    ++pruneCalls;
    lastIdentity = identity;
    identitySeen = true;
    *result = {};
    return behavior.pruneStatus;
}
} }

static void writeCurrentIdentity() {
    assert(controller && interfaceObject && wlc);
    const D::CurrentBSSLayout layout = D::currentBSSLayout(behavior.child);
    write64(static_cast<uint8_t *>(controller) + layout.controllerWLCOffset,
            reinterpret_cast<uintptr_t>(wlc));
    write64(static_cast<uint8_t *>(interfaceObject) + layout.interfaceWLCIFOffset,
            reinterpret_cast<uintptr_t>(wlcif));
    uint8_t *bss = nullptr;
    size_t recordSize = 0;
    size_t capOffset = 0;
    assert(B::sourceLayout(behavior.source, &recordSize, &capOffset));
    if (behavior.child == D::Brcm4331) {
        assert(cfg4331);
        write64(cfg4331, reinterpret_cast<uintptr_t>(wlc));
        static_cast<uint8_t *>(cfg4331)[0x0a] = 0;
        static_cast<uint8_t *>(cfg4331)[0x0b] = 0;
        static_cast<uint8_t *>(cfg4331)[0x22] = behavior.alternateCurrentBSS ? 1 : 0;
        write64(static_cast<uint8_t *>(cfg4331) + 0x320,
                behavior.idleMissingContext ? 0 : reinterpret_cast<uintptr_t>(assocContext4331));
        if (behavior.idleBadType) write32(static_cast<uint8_t *>(assocContext4331) + 0x08, 1);
        if (behavior.idleBadState) write32(static_cast<uint8_t *>(assocContext4331) + 0x0c, 1);
        bss = static_cast<uint8_t *>(record);
        write64(static_cast<uint8_t *>(cfg4331) + layout.bsscfgCurrentBSSOffset,
                reinterpret_cast<uintptr_t>(record));
        if (behavior.idleAP) static_cast<uint8_t *>(cfg4331)[0x0a] = 1;
        if (behavior.idleAssociated) static_cast<uint8_t *>(cfg4331)[0x0b] = 1;
    } else {
        auto *bytes = static_cast<uint8_t *>(wlc);
        write64(static_cast<uint8_t *>(controller) + 0x420,
                reinterpret_cast<uintptr_t>(behavior.idleSlotMismatch ? alternateCFG : wlc));
        bytes[0x3a] = behavior.alternateCurrentBSS ? 1 : 0;
        bytes[0x263a] = behavior.idleIBSSState;
        if (behavior.simulateNativeIdleSkip)
            write32(static_cast<uint8_t *>(controller) + 0x590, 0x12345678);
        if (behavior.idleAP) bytes[0x2f] = 1;
        if (behavior.idleAssociated) bytes[0x3b] = 1;
        if (behavior.idleSTAAssociated) bytes[0x10e8] = 1;
        if (behavior.idleBadType) write32(bytes + 0x3798, 1);
        if (behavior.idleBadState) write32(bytes + 0x379c, 1);
        if (behavior.idleCFGAP) bytes[0xf10 + 0x0a] = 1;
        bss = bytes + layout.inlineCurrentBSSOffset;
    }
    std::memset(bss, 0, recordSize);
    const uint8_t bssid[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    if (behavior.child == D::Brcm4331)
        std::memcpy(static_cast<uint8_t *>(cfg4331) + 0xf0, bssid, sizeof(bssid));
    if (!behavior.idleZeroBSSID) std::memcpy(bss, bssid, sizeof(bssid));
    bss[B::SSIDLengthOffset] = 3;
    std::memcpy(bss + B::SSIDOffset, "net", 3);
    write16(bss + capOffset, 0x10);
    static const uint8_t beaconHeader[B::BeaconFixedBodyBytes] = {
        48, 2, 0, 0, 221, 4, 0x00, 0x50, 0xf2, 0x01, 0xaa, 0xbb
    };
    if (behavior.noBeaconBody) {
        ieAllocation = nullptr;
        ieAllocationSize = 0;
        write64(bss + B::IEPointerOffset, 0);
        write16(bss + B::IELengthOffset, 0);
    } else {
        const bool includeCCX = behavior.ccxAssuranceEnabled || behavior.ccxAssuranceDisabled;
        const size_t tailSize = behavior.oversizedIE ? SB::MaximumIEBytes + 1 :
            (behavior.headerOnlyBody ? 0 : 3 + (includeCCX ? 7 : 0));
        ieAllocationSize = behavior.shortBeaconBody ? B::BeaconFixedBodyBytes - 1 :
            B::BeaconFixedBodyBytes + tailSize;
        ieAllocation = allocateRegion(ieAllocationSize);
        auto *body = static_cast<uint8_t *>(ieAllocation);
        std::memcpy(body, beaconHeader,
                    ieAllocationSize < sizeof(beaconHeader) ?
                        ieAllocationSize : sizeof(beaconHeader));
        if (behavior.malformedIE) {
            body[B::BeaconFixedBodyBytes] = 48;
            body[B::BeaconFixedBodyBytes + 1] = 4;
            body[B::BeaconFixedBodyBytes + 2] = 0;
        } else if (!behavior.headerOnlyBody && !behavior.shortBeaconBody) {
            body[B::BeaconFixedBodyBytes] = 48;
            body[B::BeaconFixedBodyBytes + 1] = 1;
            body[B::BeaconFixedBodyBytes + 2] = 0;
            if (includeCCX && !behavior.oversizedIE) {
                uint8_t *ccx = body + B::BeaconFixedBodyBytes + 3;
                ccx[0] = 221; ccx[1] = 5;
                ccx[2] = 0x00; ccx[3] = 0x40; ccx[4] = 0x96;
                ccx[5] = 0x0b;
                ccx[6] = behavior.ccxAssuranceEnabled ? 0x80 : 0;
            }
            if (tailSize > 3 + (includeCCX ? 7 : 0))
                std::memset(body + B::BeaconFixedBodyBytes + 3 +
                            (includeCCX ? 7 : 0), 0,
                            tailSize - 3 - (includeCCX ? 7 : 0));
        }
        write64(bss + B::IEPointerOffset, reinterpret_cast<uintptr_t>(ieAllocation));
        write16(bss + B::IELengthOffset, static_cast<uint16_t>(ieAllocationSize));
    }
}

static void prepareObjects() {
    controller = allocateRegion(0x600);
    interfaceObject = allocateRegion(0x300);
    wlc = allocateRegion(0x4000);
    wlcif = allocateRegion(0x100);
    oslHandle = allocateRegion(0x20);
    write64(static_cast<uint8_t *>(wlc) + 8, reinterpret_cast<uintptr_t>(oslHandle));
    if (behavior.child == D::Brcm4331) {
        cfg4331 = allocateRegion(0x400);
        cfg43224 = nullptr;
        alternateCFG = allocateRegion(0x400);
        assocContext4331 = allocateRegion(0x20);
        record = allocateRegion(B::Record4331Size);
    } else {
        cfg4331 = alternateCFG = nullptr;
        cfg43224 = static_cast<uint8_t *>(wlc) + 0xf10;
        record = static_cast<uint8_t *>(wlc) + D::currentBSSLayout(behavior.child).inlineCurrentBSSOffset;
    }
    writeCurrentIdentity();
}

static void expectJoinCompleteArgs() {
    joinInputExpected = record;
    joinRXExpected = wlcif;
    joinBodyExpected = ieAllocation;
    joinBodyLengthExpected = static_cast<uint32_t>(ieAllocationSize);
}

static void installJoinCompleteBody() {
    const size_t length = B::BeaconFixedBodyBytes + 3;
    auto *body = static_cast<uint8_t *>(allocateRegion(length));
    makeRefreshBody(body);
    ieAllocation = body;
    ieAllocationSize = length;
    write64(static_cast<uint8_t *>(record) + B::IEPointerOffset,
            reinterpret_cast<uintptr_t>(body));
    write16(static_cast<uint8_t *>(record) + B::IELengthOffset,
            static_cast<uint16_t>(length));
    suppressWorkerWrites = false;
}

static void resetObservations() {
    setterCalls = findCalls = disableCalls = workerCalls = outerCalls = pruneCalls = 0;
    bssInitCalls = recvParserCalls = joinCompleteCalls = clearBSSIDCalls =
        cfgMfreeCalls = downCalls = detachCalls = 0;
    cfgFreeCalls = wlcStopCalls = 0;
    injectedIEFrees = injectedRecordFrees = injectedCFGFree = injectedWLCFrees = 0;
    invalidReads = readsFromFreedRegions = scratchAllocations = scratchDeallocations = 0;
    bssRecordReads = ieAllocationReads = 0;
    scratchWasZeroed = false;
    leaseAcquisitions = 0;
    nativeIBSSCalls = 0;
    enhancedReasonConfigurationCalls = 0;
    senderCalls = builderCalls = pktFreeCalls = mbufDataCalls = 0;
    frameBodyWrites = frameBodyOutReads = frameExtendedBuilderCalls = 0;
    frameFallbackBuilderCalls = framePacketsQueued = frameQueueFailures = 0;
    mockPacketCount = 0;
    std::memset(mockPackets, 0, sizeof(mockPackets));
    senderRouteResident = builderRouteResident = false;
    activeBodyOutSlot = 0;
    lastNativeSenderPacket = nullptr;
    lastOriginalRequest = nullptr;
    joinInputExpected = joinRXExpected = nullptr;
    joinBodyExpected = nullptr;
    joinBodyLengthExpected = 0;
    joinNestedSource = nullptr;
    joinPerformBefore = joinPerformAfterNested = joinPerformAfterFree = 0;
    joinPerformAfterReplacement = 0;
    observedSetterResult = 0;
    observedDisableResult = observedWorkerDispatchResult = 0;
    nestedPerformResult = 0;
    suppressWorkerWrites = false;
    observedMutatorResult = 0;
    cfgSlotPublished = controllerSlotPublished = false;
    cfgSlotWasPublishedAtReentry = controllerSlotWasPublishedAtReentry = false;
    C::identitySeen = false;
    C::lastIdentity = {};
    leaseCurrent = true;
}

static bool regionIsLive(void *p) {
    if (!p) return false;
    for (const Region &region : regions)
        if (region.start == reinterpret_cast<uintptr_t>(p)) return region.live;
    return false;
}

static void releaseCurrentMemory(Mutator which) {
    // This models native teardown/replacement after the wrapper has registered
    // its writer. In particular, the old record still contains its former IE
    // pointer, so any later no-fault read would be visible to the region guard.
    suppressWorkerWrites = true;
    if (regionIsLive(ieAllocation)) {
        releaseRegion(ieAllocation);
        ++injectedIEFrees;
    }
    ieAllocation = nullptr;
    ieAllocationSize = 0;
    if (behavior.child == D::Brcm4331) {
        if (which == Mutator::BSSInit || which == Mutator::CfgMfree ||
            which == Mutator::Detach) {
            if (regionIsLive(record)) {
                releaseRegion(record);
                ++injectedRecordFrees;
            }
        }
        if (which == Mutator::CfgMfree || which == Mutator::Detach) {
            if (regionIsLive(cfg4331)) {
                releaseRegion(cfg4331);
                ++injectedCFGFree;
            }
        }
        if (which == Mutator::Detach && regionIsLive(wlc)) {
            releaseRegion(wlc);
            ++injectedWLCFrees;
        }
    } else if (which == Mutator::Down || which == Mutator::Detach) {
        if (regionIsLive(wlc)) {
            releaseRegion(wlc);
            ++injectedWLCFrees;
        }
        // `record` is inline in the freed WLC. Keep the stale address so the
        // no-fault reader can prove it did not touch the freed allocation.
    }
}

static int32_t nativeRecvParser(void *passedWLC, void *rx, const void *bssid,
                                uint32_t flag, const void *body, uint32_t length,
                                void *output) {
    assert(lockDepth == 0 && passedWLC == wlc && rx == wlcif && bssid && body && output);
    assert(flag <= 1 && length >= B::BeaconFixedBodyBytes);
    ++recvParserCalls;
    if (behavior.nestedParserCall && !behavior.nestedParserDidCall) {
        behavior.nestedParserDidCall = true;
        uint8_t nestedOutput[B::Record4331Size] {};
        addStackRegion(nestedOutput, sizeof(nestedOutput));
        const int32_t nested = DK::dispatchRecvParser(DK::children[0], wlc, wlcif,
            static_cast<const uint8_t *>(cfg4331) + 0xf0, 1, body, length,
            nestedOutput, imageBase() + 0x46c80);
        assert(nested == behavior.parserNativeResult);
        removeStackRegion(nestedOutput);
    }
    if (!behavior.parserNativeResult)
        writeParserRecord(output, bssid, body, length);
    return behavior.parserNativeResult;
}

static void nativeBSSInit4331(void *, void *source, void *passedCFG, void *, uint32_t, uint32_t) {
    assert(lockDepth == 0);
    ++bssInitCalls;
    if (behavior.bssInitCopySource) {
        assert(behavior.child == D::Brcm4331 && passedCFG == cfg4331 && source && regionIsLive(record));
        std::memcpy(record, source, B::Record4331Size);
        if (behavior.bssInitCorruptTarget)
            static_cast<uint8_t *>(record)[0] ^= 0x02;
        return;
    }
    if (!partialMode) releaseCurrentMemory(Mutator::BSSInit);
}

static void nativeBSSInit43224(void *, void *, void *, uint32_t) {
    assert(lockDepth == 0);
    ++bssInitCalls;
    if (!partialMode) releaseCurrentMemory(Mutator::BSSInit);
}

static void nativeJoinComplete4331(void *passedCFG, void *passedInput, void *passedRX,
                                   const void *passedBody, uint32_t passedLength) {
    assert(lockDepth == 0 && passedCFG == cfg4331 && passedInput == joinInputExpected &&
           passedRX == joinRXExpected && passedBody == joinBodyExpected &&
           passedLength == joinBodyLengthExpected);
    ++joinCompleteCalls;
    if (partialMode) return;
    if (behavior.joinCompleteReentry) {
        joinPerformBefore = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformBefore == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
    }
    void *oldIE = ieAllocation;
    const size_t oldIELength = ieAllocationSize;
    releaseCurrentMemory(Mutator::JoinComplete);
    if (behavior.joinCompleteReentry) {
        uint64_t retainedPointer = 0;
        uint16_t retainedLength = 0;
        std::memcpy(&retainedPointer, static_cast<uint8_t *>(record) + B::IEPointerOffset,
                    sizeof(retainedPointer));
        std::memcpy(&retainedLength, static_cast<uint8_t *>(record) + B::IELengthOffset,
                    sizeof(retainedLength));
        assert(oldIE && !regionIsLive(oldIE) && retainedPointer == reinterpret_cast<uintptr_t>(oldIE) &&
               retainedLength == oldIELength);
        joinPerformAfterFree = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformAfterFree == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
        assert(joinNestedSource && regionIsLive(record));
        DK::dispatchBSSInit4331(DK::children[0], wlc, joinNestedSource, cfg4331,
                                nullptr, 0x200, 0, imageBase() + 0x46ce0);
        assert(bssInitCalls == 1 && readsFromFreedRegions == 0 && invalidReads == 0);
        uint8_t nestedRecord[B::Record4331Size] {};
        B::OwnedSnapshot nestedSnapshot {};
        std::memcpy(nestedRecord, record, sizeof(nestedRecord));
        bool nestedPublished = false;
        {
            DK::MemoryGuard guard;
            // Harness state starts at epoch 1; outer JoinComplete and nested
            // BSSInit each advance it once. Check this inner generation while
            // the outer writer remains active.
            nestedPublished = DK::children[0].capture.lookup(3,
                reinterpret_cast<uintptr_t>(wlc), reinterpret_cast<uintptr_t>(cfg4331),
                reinterpret_cast<uintptr_t>(record), nestedRecord, sizeof(nestedRecord),
                &nestedSnapshot);
        }
        assert(!nestedPublished && BC::bodyless4331(nestedRecord, sizeof(nestedRecord)));
        joinPerformAfterNested = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformAfterNested == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
        installJoinCompleteBody();
        joinPerformAfterReplacement = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformAfterReplacement == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
    }
}

static void nativeJoinComplete43224(void *passedWLC, const void *passedBody,
                                    uint32_t passedLength) {
    assert(lockDepth == 0 && passedWLC == wlc && passedBody == joinBodyExpected &&
           passedLength == joinBodyLengthExpected);
    ++joinCompleteCalls;
    if (partialMode) return;
    if (behavior.joinCompleteReentry) {
        joinPerformBefore = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformBefore == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
    }
    void *oldIE = ieAllocation;
    const size_t oldIELength = ieAllocationSize;
    releaseCurrentMemory(Mutator::JoinComplete);
    if (behavior.joinCompleteReentry) {
        uint64_t retainedPointer = 0;
        uint16_t retainedLength = 0;
        std::memcpy(&retainedPointer, static_cast<uint8_t *>(record) + B::IEPointerOffset,
                    sizeof(retainedPointer));
        std::memcpy(&retainedLength, static_cast<uint8_t *>(record) + B::IELengthOffset,
                    sizeof(retainedLength));
        assert(oldIE && !regionIsLive(oldIE) && retainedPointer == reinterpret_cast<uintptr_t>(oldIE) &&
               retainedLength == oldIELength);
        joinPerformAfterFree = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformAfterFree == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
        installJoinCompleteBody();
        joinPerformAfterReplacement = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
        assert(joinPerformAfterReplacement == EBUSY && outerCalls == 0 && pruneCalls == 0 &&
               readsFromFreedRegions == 0 && invalidReads == 0);
    }
}

static uintptr_t nativeClearBSSID(void *) {
    assert(lockDepth == 0);
    ++clearBSSIDCalls;
    return 0x1234;
}

static void nativeCfgMfree(void *, void *) {
    assert(lockDepth == 0);
    ++cfgMfreeCalls;
    if (!partialMode) releaseCurrentMemory(Mutator::CfgMfree);
}

static int32_t nativeDown43224(void *) {
    assert(lockDepth == 0);
    ++downCalls;
    // The idle-candidate IBSS mode switch calls down and then continues to
    // use the same WLC for setAP/wlc_set/wlc_get/up. Only advance the writer
    // epoch here; keep the live allocations. Separate teardown tests still
    // model the native down paths that actually release state.
    if (!partialMode &&
        !(behavior.simulateNativeIdleSkip && behavior.idleIBSSState == 0 &&
          !behavior.idleIBSSReconfigureNoDown))
        releaseCurrentMemory(Mutator::Down);
    return mutatorNativeResult;
}

static int32_t nativeDetach4331(void *) {
    assert(lockDepth == 0);
    ++detachCalls;
    if (!partialMode) releaseCurrentMemory(Mutator::Detach);
    return mutatorNativeResult;
}

static int32_t nativeDetach43224(void *) {
    assert(lockDepth == 0);
    ++detachCalls;
    if (!partialMode) releaseCurrentMemory(Mutator::Detach);
    return mutatorNativeResult;
}

static void nativeCfgFree4331(void *passedWLC, void *passedCFG) {
    assert(lockDepth == 0);
    ++cfgFreeCalls;
    if (partialMode) return;
    assert(passedWLC == wlc && passedCFG == cfg4331 && cfgSlotPublished);
    DK::cfgMfree4331(nullptr, passedCFG);
    assert(cfgMfreeCalls == 1 && injectedCFGFree == 1 && injectedRecordFrees == 1);
    nestedPerformResult = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
    cfgSlotWasPublishedAtReentry = cfgSlotPublished;
    assert(cfgSlotWasPublishedAtReentry && nestedPerformResult == EBUSY);
    assert(outerCalls == 0 && pruneCalls == 0 && readsFromFreedRegions == 0 && invalidReads == 0);
    assert(scratchAllocations == 1 && scratchDeallocations == 1);
    cfgSlotPublished = false;
}

static void nativeWlcStop(void *passedController) {
    assert(lockDepth == 0);
    ++wlcStopCalls;
    if (partialMode) return;
    assert(passedController == controller && controllerSlotPublished);
    int32_t detachResult = 0;
    if (behavior.child == D::Brcm4331) detachResult = DK::detach4331(wlc);
    else detachResult = DK::detach43224(wlc);
    assert(detachResult == mutatorNativeResult && detachCalls == 1 && injectedWLCFrees == 1);
    uintptr_t publishedWLC = 0;
    const size_t offset = D::currentBSSLayout(behavior.child).controllerWLCOffset;
    std::memcpy(&publishedWLC, static_cast<uint8_t *>(controller) + offset,
                sizeof(publishedWLC));
    assert(publishedWLC == reinterpret_cast<uintptr_t>(wlc));
    nestedPerformResult = doPerform(nullptr, nullptr, nullptr, true, 0, 1);
    controllerSlotWasPublishedAtReentry = controllerSlotPublished;
    assert(controllerSlotWasPublishedAtReentry && nestedPerformResult == EBUSY);
    assert(outerCalls == 0 && pruneCalls == 0 && readsFromFreedRegions == 0 && invalidReads == 0);
    assert(scratchAllocations == 1 && scratchDeallocations == 1);
    // Match the native stop's final publication clear after reentrant admission
    // has been attempted while the detached WLC is still published.
    std::memset(static_cast<uint8_t *>(controller) + offset, 0, sizeof(publishedWLC));
    controllerSlotPublished = false;
}

static int32_t callMutator(Mutator mutator) {
    switch (mutator) {
    case Mutator::BSSInit:
        if (behavior.child == D::Brcm4331) {
            DK::bssInit4331(wlc, nullptr, cfg4331, nullptr, 0, 0);
        } else {
            DK::bssInit43224(wlc, nullptr, cfg43224, 0);
        }
        return 0;
    case Mutator::JoinComplete:
        expectJoinCompleteArgs();
        if (behavior.child == D::Brcm4331)
            DK::joinComplete4331(cfg4331, joinInputExpected, joinRXExpected,
                                 joinBodyExpected, joinBodyLengthExpected);
        else
            DK::joinComplete43224(wlc, joinBodyExpected, joinBodyLengthExpected);
        return 0;
    case Mutator::ClearBSSID: {
        void *passedCFG = behavior.clearWrongCFG ? alternateCFG : cfg4331;
        uintptr_t caller = imageBase() + (behavior.clearAlternateCallsite ? 0xb0a0b :
                                            behavior.clearWrongPC ? 0xb0fd5 : 0xb0fd6);
        const uintptr_t previousThread = activeThread;
        if (behavior.clearWrongThread) activeThread = ThreadTwo;
        const uintptr_t result = DK::dispatchClearBSSID4331(passedCFG, caller);
        activeThread = previousThread;
        return static_cast<int32_t>(result);
    }
    case Mutator::CfgMfree:
        DK::cfgMfree4331(nullptr, cfg4331);
        return 0;
    case Mutator::Down:
        return DK::down43224(wlc);
    case Mutator::Detach:
        return behavior.child == D::Brcm4331
            ? DK::detach4331(wlc) : DK::detach43224(wlc);
    case Mutator::None:
        return 0;
    }
    std::abort();
}

static void maybeInjectMutation(MutationPoint point) {
    if (behavior.mutationPoint != point || behavior.injectedMutator == Mutator::None) return;
    observedMutatorResult = callMutator(behavior.injectedMutator);
}

static void workerMutation() {
    ++workerCalls;
    assert(lockDepth == 0);
    uint8_t *bss = static_cast<uint8_t *>(record);
    if (!behavior.workerNoClearBSSID) std::memset(bss, 0, B::BSSIDSize);
    if (behavior.child == D::Brcm43224 && !behavior.workerNoClearIE) {
        write64(bss + B::IEPointerOffset, 0);
        write16(bss + B::IELengthOffset, 0);
    }
    if (ieAllocation && !behavior.workerNoClearIE) {
        releaseRegion(ieAllocation);
        ieAllocation = nullptr;
        ieAllocationSize = 0;
    }
    if (behavior.revokeLeaseInWorker) leaseCurrent = false;
}

static int32_t nativeWorker(void *argument, uint32_t flag, void *callback, void *context) {
    assert(lockDepth == 0);
    (void)argument;
    (void)callback;
    (void)context;
    if (partialMode) {
        ++workerCalls;
        // Even with a partially installed module, exercise the native
        // worker-to-sender-to-builder callsites. Resident wrappers must
        // transparently reach the original path without an active scope.
        if (senderRouteResident || behavior.exerciseSender)
            (void)invokeNativeSenderFromWorker();
        return behavior.workerResult;
    }
    maybeInjectMutation(MutationPoint::InsideWorker);
    if (suppressWorkerWrites) {
        ++workerCalls;
        return behavior.workerResultNonzero ? -17 : behavior.workerResult;
    }
    if (behavior.exerciseSender) (void)invokeNativeSenderFromWorker();
    if (suppressWorkerWrites) {
        ++workerCalls;
        return behavior.workerResultNonzero ? -17 : behavior.workerResult;
    }
    if (!behavior.workerNoClearBSSID && flag == 1) workerMutation();
    else ++workerCalls;
    return behavior.workerResultNonzero ? -17 : behavior.workerResult;
}

static MockPacket *mockPacketFor(void *packet) {
    for (size_t index = 0; index < mockPacketCount; ++index)
        if (packet == &mockPackets[index]) return &mockPackets[index];
    return nullptr;
}

static bool packetHasReasonIE(const MockPacket &packet, uint32_t reason) {
    if (packet.bodyLength != 15) return false;
    const uint8_t expected[13] = {
        0xdd, 0x0b, 0x00, 0x17, 0xf2, 0x0a, 0x02, 0x01, 0x04,
        static_cast<uint8_t>(reason), static_cast<uint8_t>(reason >> 8),
        static_cast<uint8_t>(reason >> 16), static_cast<uint8_t>(reason >> 24)
    };
    return std::memcmp(packet.data + 24 + 2, expected, sizeof(expected)) == 0;
}

static void *nativeBuilder(void *passedWLC, uint32_t subtype, const void *address1,
                           const void *address2, const void *address3,
                           uint32_t bodyLength, void **bodyOut) {
    assert(lockDepth == 0 && passedWLC == wlc && subtype == 0xa0 &&
           address2 == wlcif && address3 && bodyOut);
    (void)address1;
    ++builderCalls;
    if (bodyLength == 15) {
        ++frameExtendedBuilderCalls;
        if (behavior.failExtendedBuilder) return nullptr; // Leave bodyOut untouched.
    } else {
        assert(bodyLength == 2);
        ++frameFallbackBuilderCalls;
    }
    assert(mockPacketCount < sizeof(mockPackets) / sizeof(mockPackets[0]));
    MockPacket &packet = mockPackets[mockPacketCount++];
    packet = {};
    packet.bodyLength = bodyLength;
    *bodyOut = packet.data + 24;
    regions.push_back({reinterpret_cast<uintptr_t>(packet.data), sizeof(packet.data), true});
    if (behavior.staleFrameOwner && bodyLength == 15) leaseCurrent = false;
    return &packet;
}

static void *nativeMbufData(void *opaquePacket) {
    assert(lockDepth == 0);
    ++mbufDataCalls;
    if (behavior.failBodyWrite) return nullptr;
    MockPacket *packet = mockPacketFor(opaquePacket);
    assert(packet && !packet->freed);
    return packet->data;
}

static void nativePktFree(void *passedOSH, void *opaquePacket, int freeFlag) {
    assert(lockDepth == 0 && passedOSH == oslHandle && freeFlag == 1);
    MockPacket *packet = mockPacketFor(opaquePacket);
    assert(packet && !packet->freed && !packet->queued);
    packet->freed = true;
    ++pktFreeCalls;
    const uintptr_t start = reinterpret_cast<uintptr_t>(packet->data);
    auto region = std::find_if(regions.begin(), regions.end(), [start](const Region &item) {
        return item.start == start;
    });
    assert(region != regions.end() && region->live);
    region->live = false;
}

static void *nativeSendDisassociate(D::ChildKind child, void *passedWLC,
                                    const void *address3, uint32_t rawReason) {
    assert(lockDepth == 0 && passedWLC == wlc && address3);
    ++senderCalls;
    if (behavior.staleBeforeBuilder) leaseCurrent = false;
    if (behavior.staleEpochBeforeBuilder) {
        if (child == D::Brcm4331) DK::bssInit4331(wlc, nullptr, cfg4331, nullptr, 0, 0);
        else DK::bssInit43224(wlc, nullptr, cfg43224, 0);
    }

    void *bodyOut = nullptr;
    addStackRegion(&bodyOut, sizeof(bodyOut));
    activeBodyOutSlot = reinterpret_cast<uintptr_t>(&bodyOut);
    const uintptr_t builderPC = imageBase() +
        (child == D::Brcm4331 ? 0x4d77c : 0x7e4a4);
    void *packet = builderRouteResident
        ? DK::dispatchBuilder(DK::children[child], passedWLC, 0xa0, nullptr, wlcif,
                              address3, 2, &bodyOut, builderPC)
        : nativeBuilder(passedWLC, 0xa0, nullptr, wlcif, address3, 2, &bodyOut);
    activeBodyOutSlot = 0;
    removeStackRegion(&bodyOut);
    if (!packet) return nullptr; // In particular, never inspect an untouched out slot.

    MockPacket *mock = mockPacketFor(packet);
    assert(mock && !mock->freed && bodyOut == mock->data + 24 &&
           (mock->bodyLength == 2 || mock->bodyLength == 15));
    const uint8_t rawReasonBytes[2] = {
        static_cast<uint8_t>(rawReason), static_cast<uint8_t>(rawReason >> 8)
    };
    std::memcpy(bodyOut, rawReasonBytes, sizeof(rawReasonBytes));
    if (packetHasReasonIE(*mock, 0x89abcdefU)) ++frameBodyWrites;

    if (behavior.failSenderQueue) {
        ++frameQueueFailures;
        nativePktFree(oslHandle, packet, 1);
        return nullptr;
    }
    mock->queued = true;
    ++framePacketsQueued;
    lastNativeSenderPacket = packet;
    return packet;
}

static void *nativeSender4331(void *passedWLC, void *, const void *address3,
                              void *, void *, uint32_t rawReason) {
    return nativeSendDisassociate(D::Brcm4331, passedWLC, address3, rawReason);
}

static void *nativeSender43224(void *passedWLC, void *, const void *address3,
                               void *, uint32_t rawReason) {
    return nativeSendDisassociate(D::Brcm43224, passedWLC, address3, rawReason);
}

static void *invokeNativeSenderFromWorker() {
    if (!behavior.exerciseSender && !partialMode) return nullptr;
    const D::ChildKind child = behavior.child;
    const uintptr_t caller = imageBase() + (child == D::Brcm4331 ? 0xb0dc5 : 0x67790);
    const uint8_t alternateBSSID[6] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    const void *address3 = record;
    if (behavior.wrongSenderBSSID) {
        void *wrong = allocateRegion(sizeof(alternateBSSID));
        std::memcpy(wrong, alternateBSSID, sizeof(alternateBSSID));
        address3 = wrong;
    }
    const uintptr_t priorThread = activeThread;
    if (behavior.wrongSenderThread) activeThread = ThreadTwo;
    if (senderRouteResident) {
        const uintptr_t selectedCaller = behavior.wrongSenderCaller ? caller + 1 : caller;
        if (child == D::Brcm4331)
            lastNativeSenderPacket = DK::dispatchSender(DK::children[child], wlc, wlcif,
                address3, nullptr, wlcif, 0xabcd1357U, selectedCaller);
        else
            lastNativeSenderPacket = DK::dispatchSender(DK::children[child], wlc, wlcif,
                address3, nullptr, wlcif, 0xabcd1357U, selectedCaller);
    } else if (child == D::Brcm4331) {
        lastNativeSenderPacket = nativeSender4331(wlc, wlcif, address3, nullptr,
                                                  wlcif, 0xabcd1357U);
    } else {
        lastNativeSenderPacket = nativeSender43224(wlc, wlcif, address3, wlcif,
                                                    0xabcd1357U);
    }
    activeThread = priorThread;
    return lastNativeSenderPacket;
}

static void *nativeFindCFG(void *passedWLC, void *passedWLCIF) {
    assert(lockDepth == 0);
    ++findCalls;
    assert(passedWLC == wlc && passedWLCIF == wlcif);
    return cfg4331;
}

static int32_t nativeDisable(void *passedWLC, void *passedCFG) {
    assert(lockDepth == 0);
    ++disableCalls;
    if (partialMode) return behavior.disableResult;
    assert(passedWLC == wlc);
    void *expectedCFG = behavior.child == D::Brcm4331
        ? (behavior.wrongCFG ? alternateCFG : cfg4331)
        : (behavior.wrongCFG ? static_cast<uint8_t *>(cfg43224) + 8 : cfg43224);
    assert(passedCFG == expectedCFG);
    if (!behavior.skipWorker) {
        void *arg = behavior.child == D::Brcm4331 ? passedCFG : passedWLC;
        if (behavior.wrongWorkerArgument)
            arg = behavior.child == D::Brcm4331 ? passedWLC : passedCFG;
        const uint32_t flag = behavior.wrongWorkerFlag ? 2 : 1;
        const uintptr_t workerPC = imageBase() +
            (behavior.child == D::Brcm4331 ? 0x5e1ee : 0x901e7);
        observedWorkerDispatchResult = DK::dispatchWorker(
            DK::children[behavior.child], arg, flag, nullptr, nullptr,
            behavior.wrongWorkerCaller ? workerPC + 1 : workerPC);
    }
    return behavior.disableResult;
}

static int nativeSetter(void *passedController, void *passedInterface) {
    assert(lockDepth == 0);
    ++setterCalls;
    assert(passedController == controller);
    assert(passedInterface == (behavior.wrongInterfaceAtSetter ? wlcif : interfaceObject));
    if (partialMode) return behavior.setterResult;
    maybeInjectMutation(MutationPoint::BeforeWorker);
    if (behavior.child == D::Brcm4331) {
        if (behavior.callHelperLookup) {
            void *other = DK::dispatchFindCFG(DK::children[0], wlc, wlcif,
                                                imageBase() + 0xdaca + 7);
            assert(other == cfg4331);
        }
        const uintptr_t lookupPC = imageBase() + 0xdaca +
            (behavior.wrongFindCFGCaller ? 1 : 0);
        void *found = DK::dispatchFindCFG(DK::children[0], wlc, wlcif, lookupPC);
        assert(found == cfg4331);
        if (behavior.simulateNativeIdleSkip) {
            const auto *bytes = static_cast<const uint8_t *>(found);
            if (!bytes[0x0a] && !bytes[0x0b]) return behavior.setterResult;
        }
    } else if (behavior.simulateNativeIdleSkip) {
        auto *bytes = static_cast<uint8_t *>(wlc);
        if (!bytes[0x2f] && !bytes[0x3b]) {
            // The pinned 43224 setter calls setIBSS(false) before choosing
            // its already-idle return. A nonzero infrastructure marker takes
            // the local-cleanup path; zero remains a mode-reconfiguration
            // path and cannot be treated as a no-op candidate.
            ++nativeIBSSCalls;
            if (bytes[0x263a]) {
                write32(static_cast<uint8_t *>(controller) + 0x590, 0);
                return behavior.setterResult;
            }
            if (behavior.idleIBSSReconfigureNoDown) {
                bytes[0x263a] = 1;
                write32(static_cast<uint8_t *>(controller) + 0x590, 0);
                return behavior.setterResult;
            }
            observedMutatorResult = DK::down43224(wlc);
            // Model the remainder of INFRA mode reconfiguration after down:
            // the same WLC remains live, becomes infrastructure, and native
            // setter-local cleanup still runs. The writer epoch must prevent
            // the initial idle snapshot from authorizing a no-op.
            bytes[0x263a] = 1;
            write32(static_cast<uint8_t *>(controller) + 0x590, 0);
            return behavior.setterResult;
        }
    }
    void *passedCFG = nullptr;
    if (behavior.child == D::Brcm4331)
        passedCFG = behavior.wrongCFG ? alternateCFG : cfg4331;
    else
        passedCFG = behavior.wrongCFG ? static_cast<uint8_t *>(cfg43224) + 8 : cfg43224;
    const uintptr_t disablePC = imageBase() +
        (behavior.child == D::Brcm4331 ? 0x332ec : 0x68875);
    observedDisableResult = DK::dispatchDisable(
        DK::children[behavior.child], wlc, passedCFG,
        behavior.wrongDisableCaller ? disablePC + 1 : disablePC);
    return behavior.setterResult;
}

static int nativeOuter(void *c, void *i, void *v, LegacyWiFi::LegacyBridge::Request *r,
                       bool user64) {
    assert(lockDepth == 0);
    ++outerCalls;
    lastOriginalRequest = r;
    if (behavior.callNestedPerform)
        nestedPerformResult = DK::perform(&nativeOuter, c, i, v, r, user64, 0, 1);
    if (behavior.idleGateRefusal) leaseCurrent = false;
    void *setterInterface = behavior.wrongInterfaceAtSetter ? wlcif : i;
    if (behavior.wrongThreadAtSetter) activeThread = ThreadTwo;
    observedSetterResult = DK::dispatchSetter(DK::children[behavior.child], c,
                                               setterInterface);
    if (behavior.duplicateSetter) {
        activeThread = ThreadOne;
        observedSetterResult = DK::dispatchSetter(DK::children[behavior.child], c, i);
    }
    activeThread = ThreadOne;
    if (behavior.idleStateChangeAfterSetter) {
        if (behavior.child == D::Brcm4331)
            static_cast<uint8_t *>(cfg4331)[0x0b] = 1;
        else
            static_cast<uint8_t *>(wlc)[0x3b] = 1;
    }
    if (behavior.idleEpochChangeAfterSetter) {
        if (behavior.child == D::Brcm4331)
            DK::bssInit4331(wlc, nullptr, cfg4331, nullptr, 0, 0);
        else
            DK::bssInit43224(wlc, nullptr, cfg43224, 0);
    }
    if (behavior.idlePointerReplaceAfterSetter) {
        const size_t offset = D::currentBSSLayout(behavior.child).controllerWLCOffset;
        write64(static_cast<uint8_t *>(controller) + offset,
                reinterpret_cast<uintptr_t>(interfaceObject));
    }
    if (behavior.idleRevokeAfterSetter) leaseCurrent = false;
    return behavior.handlerResult;
}

static int doPerform(LegacyWiFi::LegacyBridge::Request *request = nullptr,
                     void *passedInterface = nullptr, void *virtualInterface = nullptr,
                     bool user64 = true, uint32_t reason = 0, uint32_t flush = 1) {
    LegacyWiFi::LegacyBridge::Request local {};
    if (!request) {
        local.type = 22;
        local.length = 12;
        request = &local;
    }
    return DK::perform(&nativeOuter, controller,
                       passedInterface ? passedInterface : interfaceObject,
                       virtualInterface, request, user64, reason, flush);
}

static void assertCleanHarness() {
    assert(lockDepth == 0 && interruptsEnabled && !interruptContext);
    assert(LegacyWiFi::DisassociateKernel::scopes == nullptr);
    assert(leasesHeld == 0);
    assert(scratchAllocations == scratchDeallocations);
    if (scratchDeallocations) assert(scratchWasZeroed);
    assert(readsFromFreedRegions == 0);
    assert(invalidReads == 0);
}

static void cleanupObjects() {
    if (ieAllocation && regionIsLive(ieAllocation)) releaseRegion(ieAllocation);
    ieAllocation = nullptr;
    for (void *p : allocations) {
        auto it = std::find_if(regions.begin(), regions.end(), [p](const Region &r) {
            return r.start == reinterpret_cast<uintptr_t>(p) && r.live;
        });
        if (it != regions.end()) {
            it->live = false;
            std::free(p);
        }
    }
    allocations.clear();
    regions.clear();
    controller = interfaceObject = wlc = wlcif = cfg4331 = cfg43224 =
        alternateCFG = assocContext4331 = record = oslHandle = nullptr;
    joinInputExpected = joinRXExpected = joinNestedSource = nullptr;
    joinBodyExpected = nullptr;
    joinBodyLengthExpected = 0;
    imageBytes.clear();
}

static void runPositive(D::ChildKind child, bool headerOnlyBody = false) {
    behavior = {};
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    behavior.headerOnlyBody = headerOnlyBody;
    resetObservations();
    initChildModule(child);
    prepareObjects();
    behavior.callHelperLookup = child == D::Brcm4331;
    const int result = doPerform();
    assert(result == 0 && outerCalls == 1 && setterCalls == 1 && disableCalls == 1 && workerCalls == 1);
    assert(observedSetterResult == behavior.setterResult);
    assert(observedDisableResult == behavior.disableResult);
    assert(observedWorkerDispatchResult == behavior.workerResult);
    assert(pruneCalls == 1 && C::identitySeen && scratchWasZeroed);
    assert(C::lastIdentity.ssidLength == 3 && std::memcmp(C::lastIdentity.ssid, "net", 3) == 0);
    assert(C::lastIdentity.fils == M::FILS::Absent);
    assert(C::lastIdentity.encryptionModes == (headerOnlyBody ? 2 : 8));
    assert(DK::ready(behavior.source));
    assertCleanHarness();
    cleanupObjects();
}

static void runIdleScenario(const std::string &name) {
    behavior = {};
    const bool is43224 = name.find("43224") != std::string::npos;
    behavior.child = is43224 ? D::Brcm43224 : D::Brcm4331;
    behavior.source = is43224 ? N::Source::Pinned43224 : N::Source::Pinned4331;
    behavior.simulateNativeIdleSkip = true;
    if (is43224) behavior.idleIBSSState = 1;
    const bool success = name.rfind("idle-success-", 0) == 0;
    const bool useEightByteRequest = name.find("8-reason") != std::string::npos;

    if (success && is43224 && !useEightByteRequest) behavior.idleIBSSState = 2;
    if (success && name.find("12-flush") != std::string::npos)
        behavior.idleZeroBSSID = true;
    if (name.find("fail-ibss-zero") != std::string::npos) {
        behavior.idleIBSSState = 0;
        behavior.idleIBSSReconfigureNoDown = name.find("no-down") != std::string::npos;
    } else if (name.find("fail-ap") != std::string::npos) {
        behavior.idleAP = true;
        behavior.skipWorker = true;
    } else if (name.find("fail-associated") != std::string::npos ||
               name.find("zero-bssid-only") != std::string::npos) {
        behavior.idleAssociated = true;
        behavior.idleZeroBSSID = name.find("zero-bssid-only") != std::string::npos;
        behavior.skipWorker = true;
    } else if (name.find("fail-sta-associated") != std::string::npos) {
        behavior.idleSTAAssociated = true;
    } else if (name.find("fail-cfg-ap") != std::string::npos) {
        behavior.idleCFGAP = true;
    } else if (name.find("fail-alternate") != std::string::npos) {
        behavior.alternateCurrentBSS = true;
    } else if (name.find("fail-type") != std::string::npos) {
        behavior.idleBadType = true;
    } else if (name.find("fail-state") != std::string::npos) {
        behavior.idleBadState = true;
    } else if (name.find("fail-context") != std::string::npos) {
        behavior.idleMissingContext = true;
    } else if (name.find("fail-slot") != std::string::npos) {
        behavior.idleSlotMismatch = true;
    } else if (name.find("gate-refusal") != std::string::npos) {
        behavior.idleGateRefusal = true;
    } else if (name.find("revoke-after-setter") != std::string::npos) {
        behavior.idleRevokeAfterSetter = true;
    } else if (name.find("epoch-after-setter") != std::string::npos) {
        behavior.idleEpochChangeAfterSetter = true;
    } else if (name.find("state-after-setter") != std::string::npos) {
        behavior.idleStateChangeAfterSetter = true;
    } else if (name.find("pointer-after-setter") != std::string::npos) {
        behavior.idlePointerReplaceAfterSetter = true;
    } else if (name.find("handler-error") != std::string::npos) {
        behavior.handlerResult = -23;
    } else if (name.find("setter-error") != std::string::npos) {
        behavior.setterResult = -24;
        behavior.handlerResult = -24;
    } else if (name.find("duplicate") != std::string::npos) {
        behavior.duplicateSetter = true;
    } else if (name.find("wrong-thread") != std::string::npos) {
        behavior.wrongThreadAtSetter = true;
    }
    if (name.find("reason") != std::string::npos) {
        behavior.exposeEnhancedReasonConfiguration = true;
        behavior.enhancedReasonConfigurationKnown = true;
        behavior.enhancedReasonEnabled = true;
    }

    resetObservations();
    initChildModule(behavior.child);
    prepareObjects();

    LegacyWiFi::LegacyBridge::Request request {};
    request.type = 22;
    request.length = useEightByteRequest ? 8 : 12;
    request.value = 0x13579bdf;
    request.padding = 0x2468ace0;
    request.userData = 0x1122334455667788ULL;
    const LegacyWiFi::LegacyBridge::Request requestBefore = request;
    const uint32_t reason = name.find("reason") != std::string::npos ? 0x89abcdefU : 0;
    const uint32_t flush = useEightByteRequest ? 0 : 1;

    if (success) {
        // A locally idle primary STA can have a stale BSSID and a stale IE
        // allocation. The no-op path must rely only on the guarded local
        // state tuple and must not dereference either current-BSS data.
        assert(ieAllocation && regionIsLive(ieAllocation));
        releaseRegion(ieAllocation); // leave the native current-BSS pointer untouched
        uint64_t storedBody = 0;
        std::memcpy(&storedBody, static_cast<uint8_t *>(record) + B::IEPointerOffset,
                    sizeof(storedBody));
        assert(storedBody == reinterpret_cast<uintptr_t>(ieAllocation));
        const auto *bss = static_cast<const uint8_t *>(record);
        if (behavior.idleZeroBSSID)
            for (size_t n = 0; n < B::BSSIDSize; ++n) assert(bss[n] == 0);
        else
            assert(bss[0] == 0x02);
    }

    const int result = doPerform(&request, nullptr, nullptr, true, reason, flush);
    if (success) {
        assert(result == 0 && outerCalls == 1 && setterCalls == 1);
        assert(observedSetterResult == 0 && disableCalls == 0 && workerCalls == 0);
        assert(pruneCalls == 0 && !C::identitySeen && senderCalls == 0 && builderCalls == 0);
        assert(downCalls == 0 && nativeIBSSCalls == (is43224 ? 1U : 0U));
        if (is43224) {
            assert(static_cast<const uint8_t *>(wlc)[0x263a] ==
                   (useEightByteRequest ? 1 : 2));
            uint32_t localCleanup = 1;
            std::memcpy(&localCleanup, static_cast<const uint8_t *>(controller) + 0x590,
                        sizeof(localCleanup));
            assert(localCleanup == 0);
        }
        assert(bssRecordReads == 0 && ieAllocationReads == 0);
        assert(leaseAcquisitions == 1 && leasesHeld == 0);
        assert(scratchAllocations == (flush ? 1U : 0U));
        assert(scratchDeallocations == scratchAllocations);
        assert(enhancedReasonConfigurationCalls == (reason ? 1U : 0U));
    } else {
        const bool staleAfterSuccess = behavior.idleRevokeAfterSetter ||
            behavior.idleEpochChangeAfterSetter || behavior.idleStateChangeAfterSetter ||
            behavior.idlePointerReplaceAfterSetter;
        const int expected = name.find("handler-error") != std::string::npos ? -23 :
            name.find("setter-error") != std::string::npos ? -24 :
            staleAfterSuccess ? ESTALE : EOPNOTSUPP;
        assert(result == expected && outerCalls == 1 && setterCalls >= 1);
        assert(pruneCalls == 0 && !C::identitySeen && leasesHeld == 0);
        assert(disableCalls == (behavior.idleAP || behavior.idleAssociated ? 1U : 0U));
        assert(workerCalls == 0);
        if (name.find("fail-ibss-zero") != std::string::npos) {
            assert(is43224 && nativeIBSSCalls == 1);
            assert(downCalls == (behavior.idleIBSSReconfigureNoDown ? 0U : 1U));
            assert(regionIsLive(wlc) && injectedWLCFrees == 0);
            assert(static_cast<const uint8_t *>(wlc)[0x263a] == 1);
            uint32_t localCleanup = 1;
            std::memcpy(&localCleanup, static_cast<const uint8_t *>(controller) + 0x590,
                        sizeof(localCleanup));
            assert(localCleanup == 0);
        }
        if (!behavior.idleEpochChangeAfterSetter)
            assert(bssRecordReads == 0 && ieAllocationReads == 0);
    }
    assert(std::memcmp(&request, &requestBefore, sizeof(request)) == 0);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    assertCleanHarness();
    cleanupObjects();
}

static unsigned nativeMutatorCalls(Mutator mutator) {
    switch (mutator) {
    case Mutator::BSSInit: return bssInitCalls;
    case Mutator::JoinComplete: return joinCompleteCalls;
    case Mutator::ClearBSSID: return clearBSSIDCalls;
    case Mutator::CfgMfree: return cfgMfreeCalls;
    case Mutator::Down: return downCalls;
    case Mutator::Detach: return detachCalls;
    case Mutator::None: return 0;
    }
    return 0;
}

static int32_t expectedMutatorResult(Mutator mutator) {
    return mutator == Mutator::ClearBSSID ? 0x1234 :
        (mutator == Mutator::Down || mutator == Mutator::Detach ? mutatorNativeResult : 0);
}

static void runMutationScenario(D::ChildKind child, Mutator mutator, MutationPoint point) {
    behavior = {};
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    behavior.injectedMutator = mutator;
    behavior.mutationPoint = point;
    resetObservations();
    initChildModule(child);
    prepareObjects();
    expectJoinCompleteArgs();
    const int result = doPerform();
    assert(outerCalls == 1 && setterCalls == 1 && disableCalls == 1 && workerCalls == 1);
    assert(nativeMutatorCalls(mutator) == 1);
    assert(observedMutatorResult == expectedMutatorResult(mutator));
    assert(injectedIEFrees == 1);
    if (child == D::Brcm4331) {
        assert(injectedRecordFrees ==
               (mutator == Mutator::JoinComplete ? 0U : 1U));
        assert(injectedCFGFree == ((mutator == Mutator::CfgMfree ||
                                    mutator == Mutator::Detach) ? 1U : 0U));
        assert(injectedWLCFrees == (mutator == Mutator::Detach ? 1U : 0U));
    } else {
        assert(injectedRecordFrees == 0 && injectedCFGFree == 0);
        assert(injectedWLCFrees == ((mutator == Mutator::Down ||
                                     mutator == Mutator::Detach) ? 1U : 0U));
    }
    assert(pruneCalls == 0 && !C::identitySeen);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    if (point == MutationPoint::BeforeWorker) assert(result == EOPNOTSUPP);
    else assert(result == ESTALE);
    assertCleanHarness();
    cleanupObjects();
}

static void runClearBSSIDScenario(bool wrongCFG, bool wrongPC, bool wrongThread,
                                  bool alternateCallsite) {
    behavior = {};
    behavior.child = D::Brcm4331;
    behavior.source = N::Source::Pinned4331;
    behavior.injectedMutator = Mutator::ClearBSSID;
    behavior.mutationPoint = MutationPoint::InsideWorker;
    behavior.clearWrongCFG = wrongCFG;
    behavior.clearWrongPC = wrongPC;
    behavior.clearWrongThread = wrongThread;
    behavior.clearAlternateCallsite = alternateCallsite;
    resetObservations();
    initChildModule(D::Brcm4331);
    prepareObjects();
    const int result = doPerform();
    assert(outerCalls == 1 && setterCalls == 1 && disableCalls == 1 && workerCalls == 1);
    assert(clearBSSIDCalls == 1 && observedMutatorResult == 0x1234);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    if (!wrongCFG && !wrongPC && !wrongThread) {
        assert(result == 0 && pruneCalls == 1 && C::identitySeen);
    } else {
        assert(result == ESTALE && pruneCalls == 0 && !C::identitySeen);
    }
    assertCleanHarness();
    cleanupObjects();
}

static void runWriterBeforePerform() {
    behavior = {};
    behavior.child = D::Brcm4331;
    behavior.source = N::Source::Pinned4331;
    resetObservations();
    initChildModule(D::Brcm4331);
    prepareObjects();
    LegacyWiFi::DisassociateMemory::Ticket writer;
    {
        DK::MemoryGuard guard;
        assert(DK::children[D::Brcm4331].memory.beginMutation(ThreadTwo, false, writer));
    }
    const int result = doPerform();
    assert(result == EBUSY && outerCalls == 0 && setterCalls == 0 && workerCalls == 0);
    assert(scratchAllocations == 1 && scratchDeallocations == 1 && pruneCalls == 0);
    {
        DK::MemoryGuard guard;
        assert(DK::children[D::Brcm4331].memory.end(writer));
    }
    assertCleanHarness();
    cleanupObjects();
}

static void runCfgFreeAdmissionWindow() {
    behavior = {};
    behavior.child = D::Brcm4331;
    behavior.source = N::Source::Pinned4331;
    resetObservations();
    initChildModule(D::Brcm4331);
    prepareObjects();
    cfgSlotPublished = true;
    DK::cfgFree4331(wlc, cfg4331);
    assert(cfgFreeCalls == 1 && cfgMfreeCalls == 1);
    assert(cfgSlotWasPublishedAtReentry && !cfgSlotPublished);
    assert(nestedPerformResult == EBUSY && outerCalls == 0 && pruneCalls == 0);
    assert(injectedIEFrees == 1 && injectedRecordFrees == 1 && injectedCFGFree == 1);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    assert(scratchAllocations == 1 && scratchDeallocations == 1);
    assertCleanHarness();
    cleanupObjects();
}

static void runWlcStopAdmissionWindow(D::ChildKind child) {
    behavior = {};
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    resetObservations();
    initChildModule(child);
    prepareObjects();
    controllerSlotPublished = true;
    if (child == D::Brcm4331) DK::wlcStop4331(controller);
    else DK::wlcStop43224(controller);
    assert(wlcStopCalls == 1 && detachCalls == 1);
    assert(controllerSlotWasPublishedAtReentry && !controllerSlotPublished);
    assert(nestedPerformResult == EBUSY && outerCalls == 0 && pruneCalls == 0);
    assert(injectedIEFrees == 1 && injectedWLCFrees == 1);
    if (child == D::Brcm4331)
        assert(injectedRecordFrees == 1 && injectedCFGFree == 1);
    else
        assert(injectedRecordFrees == 0 && injectedCFGFree == 0);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    assert(scratchAllocations == 1 && scratchDeallocations == 1);
    assertCleanHarness();
    cleanupObjects();
}

static void runRefreshScenario(const std::string &name) {
    behavior = {};
    behavior.child = D::Brcm4331;
    behavior.source = N::Source::Pinned4331;
    behavior.noBeaconBody = true;
    behavior.captureRefresh = true;
    behavior.bssInitCopySource = true;
    behavior.nestedParserCall = name == "refresh-nested-parser";
    behavior.parserNativeResult = name == "refresh-parser-error" ? -23 : 0;
    behavior.parserWriteBadCapability = name == "refresh-parser-bad-capability";
    behavior.parserWriteNonzeroBody = name == "refresh-nonzero-body";
    behavior.bssInitCorruptTarget = name == "refresh-post-init-fingerprint";
    behavior.ccxAssuranceEnabled = name == "refresh-bodyless-reason-ccx";
    behavior.exposeEnhancedReasonConfiguration = behavior.ccxAssuranceEnabled;
    behavior.enhancedReasonConfigurationKnown = behavior.ccxAssuranceEnabled;
    behavior.enhancedReasonEnabled = behavior.ccxAssuranceEnabled;
    behavior.exerciseSender = behavior.ccxAssuranceEnabled;
    if (name == "refresh-teardown") {
        behavior.injectedMutator = Mutator::BSSInit;
        behavior.mutationPoint = MutationPoint::BeforeWorker;
    }
    resetObservations();
    initChildModule(D::Brcm4331);
    prepareObjects();

    uint8_t body[B::MaximumBeaconBodyBytes] {};
    const size_t bodyLength = makeRefreshBody(body, behavior.ccxAssuranceEnabled,
                                              behavior.ccxAssuranceEnabled);
    addStackRegion(body, bodyLength);
    uint8_t output[B::Record4331Size] {};
    addStackRegion(output, sizeof(output));
    const auto *bssid = static_cast<const uint8_t *>(cfg4331) +
        (name == "refresh-parser-wrong-bssid" ? 0xf8 : 0xf0);
    uint32_t parserFlag = name == "refresh-parser-wrong-flag" ? 0 : 1;
    uintptr_t parserCaller = imageBase() +
        (name == "refresh-parser-wrong-pc" ? 0x46c81 : 0x46c80);
    const int32_t parseResult = DK::dispatchRecvParser(DK::children[0], wlc, wlcif,
        bssid, parserFlag, body, static_cast<uint32_t>(bodyLength), output, parserCaller);
    assert(parseResult == behavior.parserNativeResult && recvParserCalls >= 1);

    const bool releaseInputEarly = name == "refresh-owned-input";
    if (releaseInputEarly) {
        std::memset(body, 0, bodyLength);
        removeStackRegion(body);
    }

    if (name == "refresh-intermediate-mutation") {
        assert(DK::dispatchClearBSSID4331(cfg4331, imageBase() + 0xb0fd5) == 0x1234);
        assert(clearBSSIDCalls == 1);
    }
    if (name == "refresh-output-mutated") output[0] = 0x04;

    const bool wrongBSSPC = name == "refresh-bssinit-wrong-pc";
    const bool wrongBSSArgs = name == "refresh-bssinit-wrong-args";
    DK::dispatchBSSInit4331(DK::children[0], wlc, output, cfg4331,
        wrongBSSArgs ? wlcif : nullptr, wrongBSSArgs ? 0x201 : 0x200, 0,
        imageBase() + (wrongBSSPC ? 0x46ce1 : 0x46ce0));
    assert(bssInitCalls == 1);
    behavior.bssInitCopySource = false;

    const bool nonzeroBody = name == "refresh-nonzero-body";
    if (nonzeroBody) {
        uint64_t bodyPointer = 0;
        uint16_t bodySize = 0;
        std::memcpy(&bodyPointer, static_cast<uint8_t *>(record) + B::IEPointerOffset,
                    sizeof(bodyPointer));
        std::memcpy(&bodySize, static_cast<uint8_t *>(record) + B::IELengthOffset,
                    sizeof(bodySize));
        assert(bodyPointer == reinterpret_cast<uintptr_t>(body) && bodySize == bodyLength);
    } else {
        assert(LegacyWiFi::BSSCapture::bodyless4331(
            static_cast<uint8_t *>(record), B::Record4331Size));
    }

    removeStackRegion(output);
    LegacyWiFi::LegacyBridge::Request request {};
    request.type = 22;
    request.length = 12;
    const uint32_t reason = behavior.ccxAssuranceEnabled ? 0x89abcdefU : 0;
    const int result = doPerform(&request, nullptr, nullptr, true, reason, 1);
    if (!releaseInputEarly) removeStackRegion(body);

    const bool expectedSuccess = name == "refresh-bodyless" ||
        name == "refresh-bodyless-reason-ccx" || name == "refresh-owned-input" || nonzeroBody;
    if (expectedSuccess) {
        assert(result == 0 && outerCalls == 1 && setterCalls == 1 &&
               disableCalls == 1 && workerCalls == 1 && pruneCalls == 1);
        assert(C::identitySeen && C::lastIdentity.ssidLength == 3 &&
               std::memcmp(C::lastIdentity.ssid, "net", 3) == 0);
        assert(C::lastIdentity.encryptionModes == 8);
        if (name == "refresh-bodyless-reason-ccx") {
            assert(C::lastIdentity.fils == M::FILS::Absent);
            assert(enhancedReasonConfigurationCalls == 1 && frameExtendedBuilderCalls == 1 &&
                   frameBodyWrites == 1 && framePacketsQueued == 1);
        } else {
            assert(enhancedReasonConfigurationCalls == 0);
        }
    } else {
        assert(result != 0 && pruneCalls == 0 && !C::identitySeen);
        assert(outerCalls == 1 && recvParserCalls >= 1 &&
               bssInitCalls == (name == "refresh-teardown" ? 2U : 1U));
    }
    if (name == "refresh-teardown") {
        assert(injectedRecordFrees == 1 && result != 0 && pruneCalls == 0);
    }
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    assertCleanHarness();
    cleanupObjects();
}

static void runParserReservationRecovery() {
    behavior = {};
    behavior.child = D::Brcm4331;
    behavior.source = N::Source::Pinned4331;
    behavior.noBeaconBody = true;
    behavior.bssInitCopySource = true;
    behavior.parserNativeResult = -23;
    resetObservations();
    initChildModule(D::Brcm4331);
    prepareObjects();

    uint8_t body[B::MaximumBeaconBodyBytes] {};
    const size_t bodyLength = makeRefreshBody(body);
    addStackRegion(body, bodyLength);
    const auto *bssid = static_cast<const uint8_t *>(cfg4331) + 0xf0;
    // More distinct failed parser threads than the pending table's capacity.
    // No BSSInit follows those errors; each reservation must be cancelled.
    for (uintptr_t index = 0; index < BC::PendingCapacity + 1; ++index) {
        activeThread = 0x3000 + index;
        uint8_t output[B::Record4331Size] {};
        addStackRegion(output, sizeof(output));
        const int32_t parsed = DK::dispatchRecvParser(DK::children[0], wlc, wlcif,
            bssid, 1, body, static_cast<uint32_t>(bodyLength), output,
            imageBase() + 0x46c80);
        assert(parsed == -23);
        removeStackRegion(output);
    }
    assert(recvParserCalls == BC::PendingCapacity + 1);

    activeThread = ThreadOne;
    behavior.parserNativeResult = 0;
    uint8_t output[B::Record4331Size] {};
    addStackRegion(output, sizeof(output));
    const int32_t parsed = DK::dispatchRecvParser(DK::children[0], wlc, wlcif,
        bssid, 1, body, static_cast<uint32_t>(bodyLength), output,
        imageBase() + 0x46c80);
    assert(parsed == 0 && recvParserCalls == BC::PendingCapacity + 2);
    DK::dispatchBSSInit4331(DK::children[0], wlc, output, cfg4331,
        nullptr, 0x200, 0, imageBase() + 0x46ce0);
    assert(bssInitCalls == 1);
    behavior.bssInitCopySource = false;
    removeStackRegion(output);

    LegacyWiFi::LegacyBridge::Request request {};
    request.type = 22;
    request.length = 12;
    const int result = doPerform(&request, nullptr, nullptr, true, 0, 1);
    assert(result == 0 && outerCalls == 1 && workerCalls == 1 && pruneCalls == 1);
    assert(C::identitySeen && C::lastIdentity.ssidLength == 3);
    removeStackRegion(body);
    assert(readsFromFreedRegions == 0 && invalidReads == 0);
    assertCleanHarness();
    cleanupObjects();
}

static void runJoinCompleteReplacementWindow(D::ChildKind child) {
    behavior = {};
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    behavior.noBeaconBody = false;
    behavior.bssInitCopySource = child == D::Brcm4331;
    behavior.joinCompleteReentry = true;
    resetObservations();
    initChildModule(child);
    prepareObjects();
    expectJoinCompleteArgs();

    uint8_t body[B::MaximumBeaconBodyBytes] {};
    uint8_t output[B::Record4331Size] {};
    size_t bodyLength = 0;
    if (child == D::Brcm4331) {
        bodyLength = makeRefreshBody(body);
        addStackRegion(body, bodyLength);
        addStackRegion(output, sizeof(output));
        const int32_t parsed = DK::dispatchRecvParser(DK::children[0], wlc, wlcif,
            static_cast<uint8_t *>(cfg4331) + 0xf0, 1, body,
            static_cast<uint32_t>(bodyLength), output, imageBase() + 0x46c80);
        assert(parsed == 0 && recvParserCalls == 1);
        joinNestedSource = output;
        expectJoinCompleteArgs();
        DK::joinComplete4331(cfg4331, joinInputExpected, joinRXExpected,
                             joinBodyExpected, joinBodyLengthExpected);
        assert(bssInitCalls == 1 && joinCompleteCalls == 1);
        behavior.bssInitCopySource = false;
        removeStackRegion(output);
        removeStackRegion(body);
        joinNestedSource = nullptr;
        uint64_t currentIE = 0;
        uint16_t currentIELength = 0;
        std::memcpy(&currentIE, static_cast<uint8_t *>(record) + B::IEPointerOffset,
                    sizeof(currentIE));
        std::memcpy(&currentIELength, static_cast<uint8_t *>(record) + B::IELengthOffset,
                    sizeof(currentIELength));
        assert(currentIE == reinterpret_cast<uintptr_t>(ieAllocation) &&
               currentIELength == ieAllocationSize &&
               !BC::bodyless4331(static_cast<const uint8_t *>(record), B::Record4331Size));
    } else {
        expectJoinCompleteArgs();
        DK::joinComplete43224(wlc, joinBodyExpected, joinBodyLengthExpected);
        assert(joinCompleteCalls == 1 && bssInitCalls == 0);
    }

    assert(joinPerformBefore == EBUSY && joinPerformAfterFree == EBUSY &&
           joinPerformAfterReplacement == EBUSY);
    if (child == D::Brcm4331) assert(joinPerformAfterNested == EBUSY);
    assert(injectedRecordFrees == 0 && injectedIEFrees == 1);
    assert(scratchAllocations == scratchDeallocations && outerCalls == 0 && pruneCalls == 0);
    LegacyWiFi::LegacyBridge::Request request {};
    request.type = 22;
    request.length = 12;
    const int result = doPerform(&request, nullptr, nullptr, true, 0, 1);
    assert(result == 0 && outerCalls == 1 && workerCalls == 1 && pruneCalls == 1);
    assert(C::identitySeen && C::lastIdentity.encryptionModes == 8 &&
           readsFromFreedRegions == 0 && invalidReads == 0);
    assertCleanHarness();
    cleanupObjects();
}

static void runScenario(const std::string &name) {
    if (name.rfind("idle-", 0) == 0) return runIdleScenario(name);
    if (name.rfind("refresh-", 0) == 0) return runRefreshScenario(name);
    if (name == "parser-reservation-recovery") return runParserReservationRecovery();
    if (name == "join-complete-window-4331")
        return runJoinCompleteReplacementWindow(D::Brcm4331);
    if (name == "join-complete-window-43224")
        return runJoinCompleteReplacementWindow(D::Brcm43224);
    if (name == "positive4331") return runPositive(D::Brcm4331);
    if (name == "positive43224") return runPositive(D::Brcm43224);
    if (name == "present-header-only") return runPositive(D::Brcm4331, true);
    if (name == "writer-before-perform") return runWriterBeforePerform();
    if (name == "cfg-free-admission-window") return runCfgFreeAdmissionWindow();
    if (name == "wlc-stop-admission-window-4331") return runWlcStopAdmissionWindow(D::Brcm4331);
    if (name == "wlc-stop-admission-window-43224") return runWlcStopAdmissionWindow(D::Brcm43224);
    if (name == "nested-clear") return runClearBSSIDScenario(false, false, false, false);
    if (name == "nested-clear-alt") return runClearBSSIDScenario(false, false, false, true);
    if (name == "clear-wrong-cfg") return runClearBSSIDScenario(true, false, false, false);
    if (name == "clear-wrong-pc") return runClearBSSIDScenario(false, true, false, false);
    if (name == "clear-wrong-thread") return runClearBSSIDScenario(false, false, true, false);
    if (name.rfind("before-", 0) == 0 || name.rfind("inside-", 0) == 0) {
        const MutationPoint point = name.rfind("before-", 0) == 0
            ? MutationPoint::BeforeWorker : MutationPoint::InsideWorker;
        const std::string suffix = name.substr(point == MutationPoint::BeforeWorker ? 7 : 7);
        if (suffix == "bss4331") return runMutationScenario(D::Brcm4331, Mutator::BSSInit, point);
        if (suffix == "joincomplete4331") return runMutationScenario(D::Brcm4331, Mutator::JoinComplete, point);
        if (suffix == "cfgmfree4331") return runMutationScenario(D::Brcm4331, Mutator::CfgMfree, point);
        if (suffix == "detach4331") return runMutationScenario(D::Brcm4331, Mutator::Detach, point);
        if (suffix == "bss43224") return runMutationScenario(D::Brcm43224, Mutator::BSSInit, point);
        if (suffix == "joincomplete43224") return runMutationScenario(D::Brcm43224, Mutator::JoinComplete, point);
        if (suffix == "down43224") return runMutationScenario(D::Brcm43224, Mutator::Down, point);
        if (suffix == "detach43224") return runMutationScenario(D::Brcm43224, Mutator::Detach, point);
    }

    behavior = {};
    if (name.find("43224") != std::string::npos || name == "alternate-wlc") {
        behavior.child = D::Brcm43224;
        behavior.source = N::Source::Pinned43224;
    } else {
        behavior.child = D::Brcm4331;
        behavior.source = N::Source::Pinned4331;
    }
    if (name.rfind("reason-gate-", 0) == 0) {
        behavior.exposeEnhancedReasonConfiguration = true;
        behavior.enhancedReasonConfigurationKnown = name != "reason-gate-config-unknown";
        behavior.enhancedReasonEnabled = name != "reason-gate-disabled";
        behavior.exerciseSender = name != "reason-gate-config-unknown";
        behavior.ccxAssuranceEnabled = name.rfind("reason-gate-enabled-ccx", 0) == 0 &&
            name.find("-disabled") == std::string::npos &&
            name.find("-unknown") == std::string::npos;
        behavior.ccxAssuranceDisabled = name == "reason-gate-enabled-ccx-disabled";
        behavior.wrongSenderCaller = name == "reason-gate-enabled-ccx-wrongcaller";
        behavior.wrongSenderBSSID = name == "reason-gate-enabled-ccx-wrongbssid";
        behavior.wrongSenderThread = name == "reason-gate-enabled-ccx-wrongthread";
        behavior.staleFrameOwner = name == "reason-gate-enabled-ccx-stale-builder";
        behavior.staleBeforeBuilder = name == "reason-gate-enabled-ccx-stale-before-builder";
        behavior.staleEpochBeforeBuilder = name == "reason-gate-enabled-ccx-stale-epoch";
        behavior.failExtendedBuilder = name == "reason-gate-enabled-ccx-builder-fail";
        behavior.failBodyWrite = name == "reason-gate-enabled-ccx-write-fail";
        behavior.failSenderQueue = name == "reason-gate-enabled-ccx-queue-fail";
        if (name == "reason-gate-enabled-ccx-handler-error") behavior.handlerResult = -23;
    }
    else if (name == "allocation-fail") behavior.failAllocation = true;
    else if (name == "lease-acquire-fail") behavior.leaseAcquireAllowed = false;
    else if (name == "wrong-source") behavior.classifyOtherChild = true;
    else if (name == "handler-error") behavior.handlerResult = -23;
    else if (name == "setter-error") behavior.setterResult = -24, behavior.handlerResult = -24;
    else if (name == "skip-worker") behavior.skipWorker = true;
    else if (name == "worker-error") behavior.workerResultNonzero = true;
    else if (name == "worker-no-clear") behavior.workerNoClearBSSID = true;
    else if (name == "worker-no-clear-ie43224") behavior.workerNoClearIE = true;
    else if (name == "wrong-worker-caller") behavior.wrongWorkerCaller = true;
    else if (name == "wrong-worker-flag") behavior.wrongWorkerFlag = true;
    else if (name == "wrong-worker-argument") behavior.wrongWorkerArgument = true;
    else if (name == "wrong-find-caller") behavior.wrongFindCFGCaller = true;
    else if (name == "wrong-disable-caller") behavior.wrongDisableCaller = true;
    else if (name == "wrong-cfg") behavior.wrongCFG = true;
    else if (name == "wrong-interface") behavior.wrongInterfaceAtSetter = true;
    else if (name == "wrong-thread") behavior.wrongThreadAtSetter = true;
    else if (name == "alternate-cfg") behavior.alternateCurrentBSS = true;
    else if (name == "alternate-wlc") behavior.alternateCurrentBSS = true;
    else if (name == "no-beacon-body") behavior.noBeaconBody = true;
    else if (name == "short-beacon-body") behavior.shortBeaconBody = true;
    else if (name == "malformed-ie") behavior.malformedIE = true;
    else if (name == "oversized-ie") behavior.oversizedIE = true;
    else if (name == "revoke-lease") behavior.revokeLeaseInWorker = true;
    else if (name == "nested") behavior.callNestedPerform = true;
    else if (name == "duplicate-setter") behavior.duplicateSetter = true;
    else if (name == "prune-fail") behavior.pruneStatus = LegacyWiFi::SelectiveCache::Status::AccessFailure;
    else if (name == "reason-disabled-8-flush0-error" ||
             name == "reason-disabled-8-flush2" ||
             name == "reason-disabled-12-flush0-error" ||
             name == "reason-disabled-12-flush2" ||
             name == "reason-disabled-12-flush2-error" ||
             name == "reason-unknown-flush2" ||
             name == "reason-enabled-flush2" ||
             name == "reason-zero-query-skip") {
        behavior.exposeEnhancedReasonConfiguration = true;
        behavior.enhancedReasonConfigurationKnown = name != "reason-unknown-flush2";
        behavior.enhancedReasonEnabled = name == "reason-enabled-flush2" ||
            name == "reason-zero-query-skip";
        if (name == "reason-disabled-8-flush0-error" ||
            name == "reason-disabled-12-flush0-error" ||
            name == "reason-disabled-12-flush2-error")
            behavior.handlerResult = -23;
    }
    else if (name == "bad-request" || name == "metadata-reason" ||
             name == "metadata-flush-zero" || name == "metadata-flush-2" ||
             name == "metadata-flush-3" || name == "metadata-flush-max" ||
             name == "metadata-flush-high" || name == "user32" ||
             name == "virtual-interface" || name == "interrupt-context" ||
             name == "zero-thread") {}
    else std::abort();

    resetObservations();
    initChildModule(behavior.child);
    prepareObjects();

    LegacyWiFi::LegacyBridge::Request request {};
    request.type = 22;
    request.length = 12;
    if (name.rfind("reason-gate-", 0) == 0)
        request.length = name.find("flush2") == std::string::npos ? 8 : 12;
    if (name == "bad-request") request.length = 11;
    if (name == "reason-disabled-8-flush0-error" ||
        name == "reason-disabled-8-flush2") request.length = 8;
    request.value = 0x13579bdf;
    request.padding = 0x2468ace0;
    request.userData = 0x1122334455667788ULL;
    const LegacyWiFi::LegacyBridge::Request requestBefore = request;
    const bool configScenario = name.rfind("reason-gate-", 0) == 0 ||
        name.rfind("reason-disabled-", 0) == 0 ||
        name == "reason-unknown-flush2" || name == "reason-enabled-flush2" ||
        name == "reason-zero-query-skip";
    const uint32_t reason = name == "metadata-reason" ? 1 :
        (configScenario && name != "reason-zero-query-skip" ? 0x89abcdefU : 0);
    uint32_t flush = 1;
    if (name.rfind("reason-gate-", 0) == 0)
        flush = name.find("flush2") == std::string::npos ? 0 : 2;
    else if (name == "metadata-flush-zero") flush = 0;
    else if (name == "metadata-flush-2") flush = 2;
    else if (name == "metadata-flush-3") flush = 3;
    else if (name == "metadata-flush-max") flush = 0xffffffffU;
    else if (name == "metadata-flush-high") flush = 0x80000000U;
    else if (name.find("flush0") != std::string::npos) flush = 0;
    else if (name.find("flush2") != std::string::npos) flush = 2;
    const bool user64 = name != "user32";
    void *virtualInterface = name == "virtual-interface" ? wlcif : nullptr;
    if (name == "interrupt-context") interruptContext = true;
    if (name == "zero-thread") activeThread = 0;
    const int result = doPerform((name == "bad-request" || configScenario) ? &request : nullptr,
                                 nullptr, virtualInterface, user64, reason, flush);
    interruptContext = false;
    activeThread = ThreadOne;
    if (name.rfind("reason-gate-", 0) == 0) {
        assert(outerCalls == (name == "reason-gate-config-unknown" ? 0U : 1U));
        assert(senderCalls == (name == "reason-gate-config-unknown" ? 0U : 1U));
        if (name == "reason-gate-config-unknown") {
            assert(result == EOPNOTSUPP && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 0 && scratchAllocations == 0 && pruneCalls == 0);
            assert(builderCalls == 0 && pktFreeCalls == 0 && framePacketsQueued == 0);
        } else if (name == "reason-gate-disabled") {
            assert(result == 0 && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 0 && scratchAllocations == 0 && pruneCalls == 0);
            assert(builderCalls == 1 && frameFallbackBuilderCalls == 1);
            assert(frameExtendedBuilderCalls == 0 && pktFreeCalls == 0);
            assert(framePacketsQueued == 1 && mockPackets[0].queued &&
                   mockPackets[0].bodyLength == 2);
        } else if (name == "reason-gate-enabled-ccx-disabled") {
            assert(result == 0 && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && scratchAllocations == 0 && pruneCalls == 0);
            assert(builderCalls == 1 && frameFallbackBuilderCalls == 1);
            assert(frameExtendedBuilderCalls == 0 && pktFreeCalls == 0);
            assert(framePacketsQueued == 1 && mockPackets[0].queued &&
                   mockPackets[0].bodyLength == 2);
        } else if (name == "reason-gate-enabled-ccx-unknown" ||
                   name == "reason-gate-enabled-ccx-unknown-flush2") {
            assert(result == EOPNOTSUPP && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && pruneCalls == 0);
            assert(scratchAllocations == (name.find("flush2") != std::string::npos ? 1U : 0U));
            assert(scratchAllocations == scratchDeallocations);
            assert(builderCalls == 1 && frameFallbackBuilderCalls == 1);
            assert(frameExtendedBuilderCalls == 0 && pktFreeCalls == 0);
            assert(framePacketsQueued == 1 && mockPackets[0].queued &&
                   mockPackets[0].bodyLength == 2);
        } else if (name.rfind("reason-gate-enabled-ccx", 0) == 0 &&
                   name.find("-disabled") == std::string::npos &&
                   name.find("-unknown") == std::string::npos &&
                   name.find("wrong") == std::string::npos &&
                   name.find("stale") == std::string::npos &&
                   name.find("builder-fail") == std::string::npos &&
                   name.find("write-fail") == std::string::npos &&
                   name.find("queue-fail") == std::string::npos) {
            const bool flushPath = name.find("flush2") != std::string::npos;
            const bool handlerError = name == "reason-gate-enabled-ccx-handler-error";
            assert(result == (handlerError ? -23 : 0));
            assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 1);
            assert(pruneCalls == (flushPath ? 1U : 0U));
            assert(scratchAllocations == (flushPath ? 1U : 0U));
            assert(scratchAllocations == scratchDeallocations && leasesHeld == 0);
            assert(senderCalls == 1 && builderCalls == 1);
            assert(frameExtendedBuilderCalls == 1 && frameFallbackBuilderCalls == 0);
            assert(frameBodyOutReads == 1 && mbufDataCalls == 1 && frameBodyWrites == 1);
            assert(framePacketsQueued == 1 && pktFreeCalls == 0);
            assert(mockPackets[0].queued && !mockPackets[0].freed &&
                   mockPackets[0].bodyLength == 15 &&
                   mockPackets[0].data[24] == 0x57 && mockPackets[0].data[25] == 0x13 &&
                   packetHasReasonIE(mockPackets[0], 0x89abcdefU));
        } else if (name == "reason-gate-enabled-ccx-wrongcaller" ||
                   name == "reason-gate-enabled-ccx-wrongbssid" ||
                   name == "reason-gate-enabled-ccx-wrongthread" ||
                   name == "reason-gate-enabled-ccx-stale-builder" ||
                   name == "reason-gate-enabled-ccx-stale-before-builder" ||
                   name == "reason-gate-enabled-ccx-stale-epoch") {
            assert(result != 0 && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && scratchAllocations == 0 && pruneCalls == 0);
            assert(frameBodyWrites == 0 && framePacketsQueued == 1);
            assert(mockPackets[mockPacketCount - 1].queued &&
                   mockPackets[mockPacketCount - 1].bodyLength == 2);
            assert(frameExtendedBuilderCalls ==
                   (name == "reason-gate-enabled-ccx-stale-builder" ? 1U : 0U));
            assert(pktFreeCalls ==
                   (name == "reason-gate-enabled-ccx-stale-builder" ? 1U : 0U));
        } else if (name == "reason-gate-enabled-ccx-builder-fail") {
            assert(result == EIO && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && pruneCalls == 0 && scratchAllocations == 0);
            assert(senderCalls == 1 && builderCalls == 1 && frameExtendedBuilderCalls == 1);
            assert(frameFallbackBuilderCalls == 0 && frameBodyOutReads == 0 &&
                   mbufDataCalls == 0 && mockPacketCount == 0 && pktFreeCalls == 0);
            assert(framePacketsQueued == 0 && lastNativeSenderPacket == nullptr);
        } else if (name == "reason-gate-enabled-ccx-write-fail") {
            assert(result == EIO && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && pruneCalls == 0 && scratchAllocations == 0);
            assert(senderCalls == 1 && builderCalls == 2 && frameExtendedBuilderCalls == 1);
            assert(frameFallbackBuilderCalls == 1 && mbufDataCalls == 1);
            assert(frameBodyOutReads == 0 && frameBodyWrites == 0);
            assert(mockPacketCount == 2 && pktFreeCalls == 1 &&
                   mockPackets[0].freed && !mockPackets[0].queued &&
                   mockPackets[1].queued && !mockPackets[1].freed &&
                   mockPackets[1].bodyLength == 2);
            assert(framePacketsQueued == 1);
            assert(mockPackets[1].data[24] == 0x57 && mockPackets[1].data[25] == 0x13);
        } else if (name == "reason-gate-enabled-ccx-queue-fail") {
            assert(result == EIO && enhancedReasonConfigurationCalls == 1);
            assert(leaseAcquisitions == 1 && pruneCalls == 0 && scratchAllocations == 0);
            assert(senderCalls == 1 && builderCalls == 1 && frameExtendedBuilderCalls == 1);
            assert(frameBodyOutReads == 1 && mbufDataCalls == 1 && frameBodyWrites == 1);
            assert(mockPacketCount == 1 && pktFreeCalls == 1 && mockPackets[0].freed &&
                   !mockPackets[0].queued && mockPackets[0].bodyLength == 15 &&
                   packetHasReasonIE(mockPackets[0], 0x89abcdefU));
            assert(frameQueueFailures == 1 && framePacketsQueued == 0);
        }
    } else if (name == "allocation-fail") {
        assert(result == ENOMEM && outerCalls == 0 && scratchAllocations == 0);
    } else if (name == "lease-acquire-fail") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && scratchAllocations == 0);
    } else if (name == "wrong-source") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && scratchAllocations == 0);
    } else if (name == "handler-error") {
        assert(result == -23 && pruneCalls == 0 && outerCalls == 1);
    } else if (name == "setter-error") {
        assert(result == -24 && observedSetterResult == -24 && pruneCalls == 0);
    } else if (name == "skip-worker") {
        assert(result == EOPNOTSUPP && workerCalls == 0 && pruneCalls == 0);
    } else if (name == "worker-error") {
        assert(result == EIO && observedWorkerDispatchResult == -17 && pruneCalls == 0);
    } else if (name == "worker-no-clear" || name == "worker-no-clear-ie43224") {
        assert(result == ESTALE && pruneCalls == 0);
    } else if (name == "wrong-worker-caller" || name == "wrong-worker-flag" ||
               name == "wrong-worker-argument" || name == "wrong-disable-caller" ||
               name == "wrong-find-caller" ||
               name == "wrong-cfg" || name == "wrong-interface" ||
               name == "wrong-thread" || name == "alternate-cfg" ||
               name == "alternate-wlc" || name == "malformed-ie" ||
               name == "oversized-ie" || name == "short-beacon-body" ||
               name == "revoke-lease" ||
               name == "duplicate-setter") {
        assert(result != 0 && pruneCalls == 0);
    } else if (name == "no-beacon-body") {
        assert(result == EOPNOTSUPP && outerCalls == 1 && setterCalls == 1 &&
               disableCalls == 1 && workerCalls == 1);
        assert(pruneCalls == 0 && leaseAcquisitions == 1 && leasesHeld == 0);
        assert(scratchAllocations == 1 && scratchDeallocations == 1);
    } else if (name == "nested") {
        assert(result == 0 && nestedPerformResult == EBUSY && pruneCalls == 1);
    } else if (name == "prune-fail") {
        assert(result == ESTALE && pruneCalls == 1);
    } else if (name == "bad-request") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && scratchAllocations == 0);
    } else if (name == "metadata-flush-2" || name == "metadata-flush-3" ||
               name == "metadata-flush-max" || name == "metadata-flush-high") {
        assert(result == 0 && outerCalls == 1 && workerCalls == 1 && pruneCalls == 1);
        assert(scratchAllocations == 1 && scratchDeallocations == 1);
    } else if (name == "metadata-reason" || name == "metadata-flush-zero" ||
               name == "user32" || name == "virtual-interface" ||
               name == "interrupt-context") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && scratchAllocations == 0);
    } else if (name == "reason-disabled-8-flush0-error" ||
               name == "reason-disabled-12-flush0-error") {
        assert(result == -23 && outerCalls == 1 && lastOriginalRequest == &request);
        assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 0);
        assert(leasesHeld == 0 && scratchAllocations == 0 && scratchDeallocations == 0);
        assert(workerCalls == 1 && pruneCalls == 0);
    } else if (name == "reason-disabled-12-flush2") {
        assert(result == 0 && outerCalls == 1 && lastOriginalRequest == &request);
        assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 1);
        assert(workerCalls == 1 && pruneCalls == 1);
        assert(scratchAllocations == 1 && scratchDeallocations == 1 && leasesHeld == 0);
    } else if (name == "reason-disabled-12-flush2-error") {
        assert(result == -23 && outerCalls == 1 && lastOriginalRequest == &request);
        assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 1);
        assert(workerCalls == 1 && pruneCalls == 0);
        assert(scratchAllocations == 1 && scratchDeallocations == 1 && leasesHeld == 0);
    } else if (name == "reason-unknown-flush2") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && lastOriginalRequest == nullptr);
        assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 0);
        assert(pruneCalls == 0 && leasesHeld == 0 && scratchAllocations == 0);
    } else if (name == "reason-enabled-flush2") {
        assert(result == EOPNOTSUPP && outerCalls == 1 && lastOriginalRequest == &request);
        assert(enhancedReasonConfigurationCalls == 1 && leaseAcquisitions == 1);
        assert(workerCalls == 1 && pruneCalls == 0);
        assert(scratchAllocations == 1 && scratchDeallocations == 1 && leasesHeld == 0);
    } else if (name == "reason-disabled-8-flush2") {
        assert(result == EOPNOTSUPP && outerCalls == 0 && lastOriginalRequest == nullptr);
        assert(enhancedReasonConfigurationCalls == 0 && leaseAcquisitions == 0);
        assert(pruneCalls == 0 && leasesHeld == 0 && scratchAllocations == 0);
    } else if (name == "reason-zero-query-skip") {
        assert(result == 0 && outerCalls == 1 && lastOriginalRequest == &request);
        assert(enhancedReasonConfigurationCalls == 0 && leaseAcquisitions == 1);
        assert(workerCalls == 1 && pruneCalls == 1);
        assert(scratchAllocations == 1 && scratchDeallocations == 1 && leasesHeld == 0);
    } else if (name == "zero-thread") {
        assert(result == EBUSY && outerCalls == 0 && scratchAllocations == 1 &&
               scratchDeallocations == 1);
    }
    if (name != "wrong-source" && name != "lease-acquire-fail" &&
        name != "allocation-fail" && name != "bad-request" &&
        name != "metadata-reason" && name != "metadata-flush-zero" &&
        name != "user32" && name != "virtual-interface" &&
        name != "interrupt-context" && name != "zero-thread" &&
        name != "reason-unknown-flush2" &&
        name != "reason-disabled-8-flush2" &&
        name != "reason-gate-config-unknown") {
        assert(outerCalls == 1);
    }
    if (scratchAllocations) assert(scratchWasZeroed);
    if (configScenario) assert(std::memcmp(&request, &requestBefore, sizeof(request)) == 0);
    assertCleanHarness();
    cleanupObjects();
}

static void testPartialRoute(D::ChildKind child, unsigned failCall) {
    behavior = {};
    behavior.child = child;
    behavior.source = child == D::Brcm4331 ? N::Source::Pinned4331 : N::Source::Pinned43224;
    partialMode = true;
    resetObservations();
    initChildModule(child, failCall);
    prepareObjects();
    auto &installed = DK::children[child];
    assert(!DK::ready(behavior.source));
    // Every trampoline whose detour became resident before the route failure
    // still reaches the exact original function, with no active scope.
    unsigned route = 0;
    const auto resident = [&]() { return ++route <= failCall; };
    const bool builderResident = resident();
    const bool senderResident = resident();
    assert(builderRouteResident == builderResident && senderRouteResident == senderResident);
    if (child == D::Brcm4331) {
        if (resident()) {
            uint8_t body[B::MaximumBeaconBodyBytes] {};
            const size_t length = makeRefreshBody(body);
            uint8_t output[B::Record4331Size] {};
            addStackRegion(body, length);
            addStackRegion(output, sizeof(output));
            const int32_t value = DK::dispatchRecvParser(installed, wlc, wlcif,
                static_cast<uint8_t *>(cfg4331) + 0xf0, 1, body,
                static_cast<uint32_t>(length), output, imageBase() + 0x46c80);
            assert(value == behavior.parserNativeResult && recvParserCalls == 1);
            removeStackRegion(output);
            removeStackRegion(body);
        }
        if (resident()) {
            expectJoinCompleteArgs();
            DK::joinComplete4331(cfg4331, joinInputExpected, joinRXExpected,
                                 joinBodyExpected, joinBodyLengthExpected);
            assert(joinCompleteCalls == 1);
        }
        if (resident()) DK::bssInit4331(wlc, nullptr, cfg4331, nullptr, 0, 0);
        if (resident()) {
            const uintptr_t value = DK::dispatchClearBSSID4331(
                cfg4331, imageBase() + 0xb0fd6);
            assert(value == 0x1234 && clearBSSIDCalls == 1);
        }
        if (resident()) DK::cfgMfree4331(nullptr, cfg4331);
        if (resident()) DK::cfgFree4331(wlc, cfg4331);
        if (resident()) {
            const int32_t value = DK::detach4331(wlc);
            assert(value == mutatorNativeResult && detachCalls == 1);
        }
        if (resident()) DK::wlcStop4331(controller);
    } else {
        if (resident()) {
            expectJoinCompleteArgs();
            DK::joinComplete43224(wlc, joinBodyExpected, joinBodyLengthExpected);
            assert(joinCompleteCalls == 1);
        }
        if (resident()) DK::bssInit43224(wlc, nullptr, cfg43224, 0);
        if (resident()) {
            const int32_t value = DK::down43224(wlc);
            assert(value == mutatorNativeResult && downCalls == 1);
        }
        if (resident()) {
            const int32_t value = DK::detach43224(wlc);
            assert(value == mutatorNativeResult && detachCalls == 1);
        }
        if (resident()) DK::wlcStop43224(controller);
    }
    if (resident()) {
        const uintptr_t pc = imageBase() + (child == D::Brcm4331 ? 0x5e1ee : 0x901e7);
        void *arg = child == D::Brcm4331 ? cfg4331 : wlc;
        const int32_t value = DK::dispatchWorker(installed, arg, 1, nullptr, nullptr, pc);
        assert(value == behavior.workerResult && workerCalls == 1);
    }
    if (child == D::Brcm4331 && resident()) {
        void *value = DK::dispatchFindCFG(installed, wlc, wlcif, imageBase() + 0xdaca);
        assert(value == cfg4331 && findCalls == 1);
    }
    if (resident()) {
        const uintptr_t pc = imageBase() + (child == D::Brcm4331 ? 0x332ec : 0x68875);
        void *cfg = child == D::Brcm4331 ? cfg4331 : cfg43224;
        const int32_t value = DK::dispatchDisable(installed, wlc, cfg, pc);
        assert(value == behavior.disableResult && disableCalls == 1);
    }
    if (resident()) {
        const int value = DK::dispatchSetter(installed, controller, interfaceObject);
        assert(value == behavior.setterResult && setterCalls == 1);
    }
    const unsigned expectedRouteCount = child == D::Brcm4331 ? 14 : 10;
    assert(route == expectedRouteCount);
    if (child == D::Brcm4331) {
        assert(recvParserCalls == (failCall >= 3 ? 1U : 0U));
        assert(joinCompleteCalls == (failCall >= 4 ? 1U : 0U));
        assert(bssInitCalls == (failCall >= 5 ? 1U : 0U));
        assert(clearBSSIDCalls == (failCall >= 6 ? 1U : 0U));
        assert(cfgMfreeCalls == (failCall >= 7 ? 1U : 0U));
        assert(cfgFreeCalls == (failCall >= 8 ? 1U : 0U));
        assert(detachCalls == (failCall >= 9 ? 1U : 0U));
        assert(wlcStopCalls == (failCall >= 10 ? 1U : 0U));
        assert(workerCalls == (failCall >= 11 ? 1U : 0U));
        assert(findCalls == (failCall >= 12 ? 1U : 0U));
        assert(disableCalls == (failCall >= 13 ? 1U : 0U));
        assert(setterCalls == (failCall >= 14 ? 1U : 0U));
    } else {
        assert(joinCompleteCalls == (failCall >= 3 ? 1U : 0U));
        assert(bssInitCalls == (failCall >= 4 ? 1U : 0U));
        assert(downCalls == (failCall >= 5 ? 1U : 0U));
        assert(detachCalls == (failCall >= 6 ? 1U : 0U));
        assert(wlcStopCalls == (failCall >= 7 ? 1U : 0U));
        assert(workerCalls == (failCall >= 8 ? 1U : 0U));
        assert(disableCalls == (failCall >= 9 ? 1U : 0U));
        assert(setterCalls == (failCall >= 10 ? 1U : 0U));
    }
    assert(pruneCalls == 0 && DK::children[child].active == 0);
    if (workerCalls) {
        assert(senderCalls == 1 && builderCalls == 1 && pktFreeCalls == 0);
        assert(framePacketsQueued == 1 && mockPacketCount == 1 &&
               mockPackets[0].queued && mockPackets[0].bodyLength == 2);
        assert(frameExtendedBuilderCalls == 0 && frameBodyOutReads == 0);
    } else {
        assert(senderCalls == 0 && builderCalls == 0 && framePacketsQueued == 0);
    }
    assertCleanHarness();
    cleanupObjects();
    partialMode = false;
}

int main(int argc, char **argv) {
    assert(argc == 2);
    const std::string scenario = argv[1];
    if (scenario.rfind("partial4331-", 0) == 0) {
        testPartialRoute(D::Brcm4331, static_cast<unsigned>(std::stoi(scenario.substr(12))));
    } else if (scenario.rfind("partial43224-", 0) == 0) {
        testPartialRoute(D::Brcm43224, static_cast<unsigned>(std::stoi(scenario.substr(13))));
    } else {
        runScenario(scenario);
    }
    puts("legacy disassociate kernel harness passed");
    return 0;
}
'''


class DisassociateKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("clang++")
        if not compiler:
            raise unittest.SkipTest("clang++ is required for the disassociate harness")
        cls.temp = tempfile.TemporaryDirectory(prefix="legacy-disassociate-kernel-")
        root = Path(cls.temp.name)
        mock = root / "mock"
        (mock / "Headers").mkdir(parents=True)
        (mock / "IOKit").mkdir(parents=True)
        (mock / "machine").mkdir(parents=True)
        (mock / "Headers/kern_patcher.hpp").write_text(MOCK_HEADERS)
        (mock / "IOKit/IOLocks.h").write_text(IOLOCKS_STUB)
        (mock / "machine/machine_routines.h").write_text(MACHINE_ROUTINES_STUB)
        source = root / "disassociate_harness.cpp"
        binary = root / "disassociate_harness"
        source.write_text(HARNESS)
        subprocess.run(
            [compiler, "-std=c++14", "-Wall", "-Wextra",
             "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
             "-I", str(mock), "-I", str(PROJECT / "src"),
             str(PROJECT / "src/legacy_wifi_compat/disassociate_admission.cpp"),
             str(source), "-o", str(binary)],
            check=True, capture_output=True, text=True, timeout=120,
        )
        cls.binary = binary

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def run_scenario(self, scenario):
        result = subprocess.run(
            [str(self.binary), scenario], check=True, capture_output=True,
            text=True, timeout=30,
        )
        self.assertIn("passed", result.stdout)

    def test_successful_both_children_and_present_header_without_ie_tail(self):
        for scenario in ("positive4331", "positive43224", "present-header-only"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_proven_idle_native_skip_is_a_noop_without_reading_stale_bss(self):
        for scenario in (
            "idle-success-4331-8-reason", "idle-success-4331-12-flush-reason",
            "idle-success-43224-8-reason", "idle-success-43224-12-flush-reason",
        ):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_idle_noop_rejects_incomplete_or_nonprimary_state(self):
        for scenario in (
            "idle-fail-ap-4331", "idle-fail-associated-4331",
            "idle-fail-alternate-4331", "idle-fail-type-4331", "idle-fail-state-4331",
            "idle-fail-context-4331",
            "idle-fail-ap-43224", "idle-fail-associated-43224",
            "idle-fail-cfg-ap-43224", "idle-fail-sta-associated-43224",
            "idle-fail-alternate-43224", "idle-fail-type-43224",
            "idle-fail-state-43224", "idle-fail-slot-43224",
            "idle-fail-ibss-zero-43224", "idle-fail-ibss-zero-no-down-43224",
            "idle-zero-bssid-only-4331", "idle-zero-bssid-only-43224",
        ):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_idle_noop_rechecks_owner_gate_epoch_and_native_results(self):
        for scenario in (
            "idle-gate-refusal-4331", "idle-gate-refusal-43224",
            "idle-revoke-after-setter-4331", "idle-revoke-after-setter-43224",
            "idle-epoch-after-setter-4331", "idle-epoch-after-setter-43224",
            "idle-state-after-setter-4331", "idle-state-after-setter-43224",
            "idle-pointer-after-setter-4331", "idle-pointer-after-setter-43224",
            "idle-handler-error-4331", "idle-setter-error-43224",
            "idle-duplicate-4331", "idle-wrong-thread-43224",
        ):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_original_errors_and_missing_completion_never_prune(self):
        for scenario in ("handler-error", "setter-error", "skip-worker",
                         "worker-error", "worker-no-clear", "worker-no-clear-ie43224"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_wrong_callers_arguments_and_child_state_fail_closed(self):
        for scenario in ("wrong-source", "wrong-interface", "wrong-thread",
                         "wrong-disable-caller", "wrong-cfg", "alternate-cfg",
                         "wrong-find-caller",
                         "alternate-wlc", "wrong-worker-caller", "wrong-worker-flag",
                         "wrong-worker-argument", "revoke-lease", "duplicate-setter"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_invalid_ie_request_allocation_and_prune_fail_closed(self):
        for scenario in ("malformed-ie", "oversized-ie", "short-beacon-body",
                         "no-beacon-body", "bad-request",
                         "allocation-fail", "lease-acquire-fail", "prune-fail"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_metadata_shape_and_execution_context_guards(self):
        for scenario in ("metadata-reason", "metadata-flush-zero", "user32",
                         "virtual-interface", "interrupt-context", "zero-thread"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_native_nonzero_flush_boolean_is_accepted(self):
        for scenario in ("metadata-flush-2", "metadata-flush-3", "metadata-flush-max",
                         "metadata-flush-high"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_enhanced_reason_configuration_gate_and_flush_paths(self):
        for scenario in ("reason-disabled-8-flush0-error",
                         "reason-disabled-12-flush0-error",
                         "reason-disabled-12-flush2",
                         "reason-disabled-12-flush2-error",
                         "reason-unknown-flush2", "reason-enabled-flush2",
                         "reason-disabled-8-flush2", "reason-zero-query-skip"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_reason_ie_uses_native_sender_builder_and_owner_gates(self):
        scenarios = (
            "reason-gate-disabled",
            "reason-gate-config-unknown",
            "reason-gate-enabled-ccx",
            "reason-gate-enabled-ccx-flush2",
            "reason-gate-enabled-ccx-43224",
            "reason-gate-enabled-ccx-flush2-43224",
            "reason-gate-enabled-ccx-disabled",
            "reason-gate-enabled-ccx-unknown",
            "reason-gate-enabled-ccx-unknown-flush2",
            "reason-gate-enabled-ccx-handler-error",
            "reason-gate-enabled-ccx-wrongcaller",
            "reason-gate-enabled-ccx-wrongbssid",
            "reason-gate-enabled-ccx-wrongthread",
            "reason-gate-enabled-ccx-stale-builder",
            "reason-gate-enabled-ccx-stale-before-builder",
            "reason-gate-enabled-ccx-stale-epoch",
            "reason-gate-enabled-ccx-builder-fail",
            "reason-gate-enabled-ccx-write-fail",
            "reason-gate-enabled-ccx-queue-fail",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_nested_scope_is_rejected_without_blocking_outer_operation(self):
        self.run_scenario("nested")

    def test_selected_memory_epoch_rejects_live_writers_and_exact_nested_clear(self):
        for scenario in ("writer-before-perform", "nested-clear", "nested-clear-alt"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_cleanup_callbacks_keep_publication_writers_through_reentry(self):
        for scenario in ("cfg-free-admission-window", "wlc-stop-admission-window-4331",
                         "wlc-stop-admission-window-43224"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_4331_recv_refresh_snapshot_is_owned_one_shot_and_fail_closed(self):
        scenarios = (
            "refresh-bodyless",
            "refresh-owned-input",
            "refresh-bodyless-reason-ccx",
            "refresh-nonzero-body",
            "refresh-parser-wrong-pc",
            "refresh-parser-wrong-bssid",
            "refresh-parser-wrong-flag",
            "refresh-parser-error",
            "refresh-parser-bad-capability",
            "refresh-bssinit-wrong-pc",
            "refresh-bssinit-wrong-args",
            "refresh-output-mutated",
            "refresh-intermediate-mutation",
            "refresh-nested-parser",
            "refresh-post-init-fingerprint",
            "refresh-teardown",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)
        self.run_scenario("parser-reservation-recovery")

    def test_join_complete_fences_replacement_and_nested_bssinit(self):
        scenarios = (
            "join-complete-window-4331",
            "join-complete-window-43224",
            "before-joincomplete4331",
            "inside-joincomplete4331",
            "before-joincomplete43224",
            "inside-joincomplete43224",
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_released_child_memory_never_reaches_reader_or_pruner(self):
        scenarios = tuple(
            f"{stage}-{mutator}"
            for stage in ("before", "inside")
            for mutator in ("bss4331", "joincomplete4331", "cfgmfree4331", "detach4331",
                            "bss43224", "joincomplete43224", "down43224", "detach43224")
        )
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_nested_clear_requires_exact_cfg_caller_and_thread(self):
        for scenario in ("clear-wrong-cfg", "clear-wrong-pc", "clear-wrong-thread"):
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)

    def test_partial_resident_routes_always_forward_to_native(self):
        scenarios = tuple([f"partial4331-{n}" for n in range(1, 15)] +
                          [f"partial43224-{n}" for n in range(1, 11)])
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                self.run_scenario(scenario)


if __name__ == "__main__":
    unittest.main()
