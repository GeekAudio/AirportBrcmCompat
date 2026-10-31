#include "scan_sequence_kernel.hpp"
#include "scan_sequence.hpp"
#include "provider_contract.hpp"
#include "scan_bridge.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IONotifier.h>
#include <IOKit/IOMessage.h>
#include <kern/thread_call.h>
#include <sys/errno.h>
#include <sys/proc.h>

namespace LegacyWiFi {
namespace ScanSequenceKernel {
namespace {

namespace E = EventContracts;
namespace S = ScanSequence;

constexpr size_t MaximumSessions = 8;
constexpr uintptr_t StartScanOffset = 0x615e8;
constexpr uintptr_t StartScanRequestCallOffset = 0x618fd;
constexpr uintptr_t StartScanErrorDoneCallOffset = 0x61917;
constexpr uintptr_t StartScanRequestNodeCallOffset = 0x6189c;
constexpr uintptr_t StartScanPendingCompareCallOffset = 0x619a8;
constexpr uintptr_t AllocateScanRequestNodeOffset = 0x62888;
constexpr uintptr_t AllocateScanRequestCopyCallOffset = 0x6290a;
constexpr const char *StartScanSymbol =
    "__ZN18IO80211ScanManager9startScanEP20apple80211_scan_data";
constexpr const char *AllocateScanRequestNodeSymbol =
    "__ZL17_allocScanReqNodeP20apple80211_scan_dataP29apple80211_scan_multiple_datai";
constexpr const char *RequestIoctlSymbol =
    "__ZN17IO80211Controller22apple80211RequestIoctlEjiP16IO80211InterfacePv";
constexpr const char *ControllerScanDoneSymbol =
    "__ZN17IO80211Controller8scanDoneE10scanSourcei";
constexpr const char *MemcmpSymbol = "_memcmp";
constexpr const char *MemcpySymbol = "_memcpy";

static_assert(S::SingleScanSize == ProviderContract::SingleRequestMaxSize,
              "split scan job must cover El Cap's fixed scan_data read size");

struct SpinLock {
    IOSimpleLock *lock = nullptr;
    IOInterruptState interruptState = 0;
};
SpinLock registryLock {};
OSObject *eventOwner = nullptr;
EventContracts::EventRouter *eventRouter = nullptr;
API globalAPI {};
StartScan verifiedStartScan = nullptr;
ScanOwner::GetResult verifiedGetResult = nullptr;
volatile uint32_t initialized = 0;

struct Session {
    S::Coordinator coordinator;
    SpinLock stateLock {};
    ScanAggregate::Store aggregate;
    IOService *controller = nullptr;
    IOService *interface = nullptr;
    OSObject *manager = nullptr;
    IOWorkLoop *workLoop = nullptr;
    IOCommandGate *gate = nullptr;
    IOTimerEventSource *timer = nullptr;
    thread_call_t cleanupCall = nullptr;
    thread_call_t cancelCall = nullptr;
    thread_call_t completionCall = nullptr;
    IONotifier *interfaceNotifier = nullptr;
    IONotifier *controllerNotifier = nullptr;
    ScanOwner::Token owner {};
    S::PendingCancellation ownerCancellation {};
    S::CancelledOwners cancelledOwners {};
    S::PendingCompletions completionRecords {};
    bool cancelledOwnerOverflow = false;
    S::Deferred pending = nullptr;
    void *pendingOwner = nullptr;
    uint64_t pendingGeneration = 0;
    bool used = false;
    volatile uint32_t setupReady = 0;
    volatile uint32_t retiring = 0;
    volatile uint32_t cleanupQueued = 0;
    volatile uint32_t cleaned = 0;
    volatile uint32_t cleaning = 0;
    bool gateAdded = false;
    bool timerAdded = false;
    volatile uint32_t submitting = 0;
};

Session sessions[MaximumSessions];

void enterSpin(SpinLock &lock) {
    lock.interruptState = IOSimpleLockLockDisableInterrupt(lock.lock);
}

void leaveSpin(SpinLock &lock) {
    IOSimpleLockUnlockEnableInterrupt(lock.lock, lock.interruptState);
}

void enterLock(void *opaque) {
    enterSpin(*static_cast<SpinLock *>(opaque));
}

void leaveLock(void *opaque) {
    leaveSpin(*static_cast<SpinLock *>(opaque));
}

void lockRegistry() {
    enterSpin(registryLock);
}

void unlockRegistry() {
    leaveSpin(registryLock);
}

bool isRetiring(const Session &session) {
    return __atomic_load_n(&session.retiring, __ATOMIC_ACQUIRE) != 0;
}

void markRetiring(Session &session) {
    __atomic_store_n(&session.retiring, 1U, __ATOMIC_RELEASE);
}

bool isCleaned(const Session &session) {
    return __atomic_load_n(&session.cleaned, __ATOMIC_ACQUIRE) != 0;
}

bool isSetupReady(const Session &session) {
    return __atomic_load_n(&session.setupReady, __ATOMIC_ACQUIRE) != 0;
}

bool isCleaning(const Session &session) {
    return __atomic_load_n(&session.cleaning, __ATOMIC_ACQUIRE) != 0;
}

bool isSubmitting(const Session &session) {
    return __atomic_load_n(&session.submitting, __ATOMIC_ACQUIRE) != 0;
}

void setSubmitting(Session &session, bool value) {
    __atomic_store_n(&session.submitting, value ? 1U : 0U, __ATOMIC_RELEASE);
}

void finishSubmitting(Session &session) {
    lockRegistry();
    setSubmitting(session, false);
    if ((isRetiring(session) || session.ownerCancellation.ownerPending()) &&
        !isCleaning(session) && !isCleaned(session) && session.cancelCall)
        thread_call_enter(session.cancelCall);
    unlockRegistry();
}

bool inRange(size_t imageSize, size_t offset, size_t count) {
    return offset <= imageSize && count <= imageSize - offset;
}

bool callTargets(const uint8_t *image, size_t imageSize, size_t offset,
                 uintptr_t base, uintptr_t target) {
    if (!image || offset > imageSize || imageSize - offset < 5 ||
        image[offset] != 0xe8 || target < base) return false;
    int32_t relative = 0;
    memcpy(&relative, image + offset + 1, sizeof(relative));
    const int64_t resolved = static_cast<int64_t>(offset) + 5 + relative;
    return resolved >= 0 && static_cast<uint64_t>(resolved) == target - base;
}

bool callTargetIs(const uint8_t *image, size_t imageSize, size_t offset,
                  uintptr_t base, uintptr_t target) {
    if (!image || offset > imageSize || imageSize - offset < 5 ||
        image[offset] != 0xe8 || base > UINTPTR_MAX - offset - 5)
        return false;
    int32_t relative = 0;
    memcpy(&relative, image + offset + 1, sizeof(relative));
    uintptr_t resolved = 0;
    return ScanOwner::Core::addRelative32(base + offset + 5, relative, &resolved) &&
        resolved == target;
}

bool verifyStartScan(KernelPatcher &patcher, size_t index,
                     mach_vm_address_t address, size_t size,
                     StartScan *entry) {
    if (!address || !entry || size > UINTPTR_MAX - address) return false;
    const uint8_t *image = reinterpret_cast<const uint8_t *>(address);
    const uint8_t startPrefix[] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,
        0x53,0x48,0x81,0xec,0xb8,0x00,0x00,0x00,0x48,0x89,0xf3,0x49,0x89,0xfe
    };
    const uint8_t ioctlArguments[] = {
        0x49,0x8b,0x7e,0x50,0x49,0x8b,0x4e,0x58,0xbe,0xc8,0x69,0x28,0x80,
        0xba,0x0a,0x00,0x00,0x00,0x4d,0x89,0xf8
    };
    const uint8_t errorDoneArguments[] = {
        0x49,0x8b,0x7e,0x50,0x31,0xf6,0x44,0x89,0xe2
    };
    const uint8_t requestNodeArguments[] = {
        0x31,0xf6,0x4c,0x89,0xff,0x44,0x89,0xe2
    };
    const uint8_t pendingCompareArguments[] = {
        0x49,0x8d,0x7d,0x10,0xba,0x54,0x09,0,0,0x4c,0x89,0xfe
    };
    const uint8_t allocationCopyArguments[] = {
        0x4d,0x85,0xe4,0x74,0x28,0x48,0x8d,0x7b,0x10,
        0xba,0x54,0x09,0,0,0x4c,0x89,0xe6,0xeb,0x29
    };
    if (!inRange(size, StartScanOffset, sizeof(startPrefix)) ||
        memcmp(image + StartScanOffset, startPrefix, sizeof(startPrefix)) ||
        !inRange(size, StartScanRequestCallOffset - sizeof(ioctlArguments),
                 sizeof(ioctlArguments) + 5) ||
        memcmp(image + StartScanRequestCallOffset - sizeof(ioctlArguments),
               ioctlArguments, sizeof(ioctlArguments)) ||
        !inRange(size, StartScanErrorDoneCallOffset - sizeof(errorDoneArguments),
                 sizeof(errorDoneArguments) + 5) ||
        memcmp(image + StartScanErrorDoneCallOffset - sizeof(errorDoneArguments),
               errorDoneArguments, sizeof(errorDoneArguments)) ||
        !inRange(size, StartScanRequestNodeCallOffset - sizeof(requestNodeArguments),
                 sizeof(requestNodeArguments) + 5) ||
        memcmp(image + StartScanRequestNodeCallOffset - sizeof(requestNodeArguments),
               requestNodeArguments, sizeof(requestNodeArguments)) ||
        !inRange(size, StartScanPendingCompareCallOffset - sizeof(pendingCompareArguments),
                 sizeof(pendingCompareArguments) + 5) ||
        memcmp(image + StartScanPendingCompareCallOffset - sizeof(pendingCompareArguments),
               pendingCompareArguments, sizeof(pendingCompareArguments)) ||
        !inRange(size, 0x628ce, sizeof(allocationCopyArguments)) ||
        memcmp(image + 0x628ce, allocationCopyArguments,
               sizeof(allocationCopyArguments))) return false;

    patcher.clearError();
    const uintptr_t start = patcher.solveSymbol(index, StartScanSymbol, address, size);
    const uintptr_t allocateNode = patcher.solveSymbol(
        index, AllocateScanRequestNodeSymbol, address, size);
    const uintptr_t ioctl = patcher.solveSymbol(index, RequestIoctlSymbol, address, size);
    const uintptr_t scanDone = patcher.solveSymbol(index, ControllerScanDoneSymbol,
                                                   address, size);
    const uintptr_t memcmpAddress = patcher.solveSymbol(
        KernelPatcher::KernelID, MemcmpSymbol);
    const uintptr_t memcpyAddress = patcher.solveSymbol(
        KernelPatcher::KernelID, MemcpySymbol);
    const bool solved = patcher.getError() == KernelPatcher::Error::NoError;
    patcher.clearError();
    if (!solved || start != address + StartScanOffset ||
        allocateNode != address + AllocateScanRequestNodeOffset || !ioctl || !scanDone ||
        !memcmpAddress || !memcpyAddress ||
        !callTargets(image, size, StartScanRequestCallOffset, address, ioctl) ||
        !callTargets(image, size, StartScanErrorDoneCallOffset, address, scanDone) ||
        !callTargets(image, size, StartScanRequestNodeCallOffset, address, allocateNode) ||
        !callTargetIs(image, size, StartScanPendingCompareCallOffset, address,
                      memcmpAddress) ||
        !callTargetIs(image, size, AllocateScanRequestCopyCallOffset, address,
                      memcpyAddress))
        return false;
    *entry = reinterpret_cast<StartScan>(start);
    return true;
}

bool resolveProviderEvents(KernelPatcher &patcher, size_t index,
                           mach_vm_address_t address, size_t size,
                           E::ProviderSymbols &symbols) {
    patcher.clearError();
    symbols = {
        patcher.solveSymbol(index,"__ZN16IO80211Interface10getBSDNameEv",address,size),
        patcher.solveSymbol(index,"__ZN16IO80211Interface11postMessageEjPvm",address,size),
        patcher.solveSymbol(index,"__Z27IO80211InterfacePostMessagePcjPvm",address,size),
        patcher.solveSymbol(index,"__ZN18IO80211ScanManager8scanDoneEb",address,size),
        patcher.solveSymbol(index,"__ZN16IO80211QueueCall12kev_post_msgEP7kev_msg",address,size)
    };
    const bool solved = patcher.getError() == KernelPatcher::Error::NoError;
    patcher.clearError();
    return solved;
}

void releaseJobs(void *bytes, size_t size) {
    if (!bytes) return;
    memset(bytes, 0, size);
    IOFree(bytes, size);
}

void reportFailure(void *, void *, int error);
void releaseOwner(Session &session);
void releaseOwnerIfIdle(Session &session);
bool hasAggregate(Session &session);
void clearAggregate(Session &session);

void *allocateJobs(size_t size) {
    return IOMallocZero(size);
}

void actionCallback(S::Deferred callback, void *owner, uint64_t generation) {
    if (callback) callback(owner, generation);
}

struct GateCall {
    Session *session = nullptr;
    S::Deferred callback = nullptr;
    void *owner = nullptr;
    uint64_t generation = 0;
    int error = ENXIO;
};

IOReturn runDeferredAction(OSObject *, void *argument, void *, void *, void *) {
    auto *call = static_cast<GateCall *>(argument);
    if (!call || !call->session || !call->session->workLoop ||
        !call->session->workLoop->inGate()) return kIOReturnNotReady;
    call->error = 0;
    actionCallback(call->callback, call->owner, call->generation);
    return kIOReturnSuccess;
}

IOReturn runOnGate(void *context, S::Deferred callback, void *owner,
                   uint64_t generation) {
    auto *session = static_cast<Session *>(context);
    if (!session || !session->gate || !session->workLoop || !callback) return ENXIO;
    GateCall call {session, callback, owner, generation, EIO};
    if (session->workLoop->inGate()) {
        (void)runDeferredAction(nullptr, &call, nullptr, nullptr, nullptr);
        return call.error;
    }
    const IOReturn result = session->gate->runAction(runDeferredAction, &call);
    return result == kIOReturnSuccess ? call.error : EIO;
}

IOReturn armTimerAction(OSObject *, void *argument, void *, void *, void *) {
    auto *call = static_cast<GateCall *>(argument);
    if (!call || !call->session || !call->session->timer ||
        !call->session->workLoop || !call->session->workLoop->inGate() ||
        !call->callback) return kIOReturnNotReady;
    Session &session = *call->session;
    if (isRetiring(session) || isCleaned(session)) return kIOReturnAborted;
    if (session.pending) return kIOReturnBusy;
    session.pending = call->callback;
    session.pendingOwner = call->owner;
    session.pendingGeneration = call->generation;
    const IOReturn result = session.timer->setTimeoutMS(1);
    if (result != kIOReturnSuccess) {
        session.pending = nullptr;
        session.pendingOwner = nullptr;
        session.pendingGeneration = 0;
        return result;
    }
    return kIOReturnSuccess;
}

IOReturn schedule(void *context, S::Deferred callback, void *owner,
                  uint64_t generation) {
    auto *session = static_cast<Session *>(context);
    if (!session || !session->gate || !callback || isRetiring(*session)) return ENXIO;
    GateCall call {session, callback, owner, generation, EIO};
    if (session->workLoop && session->workLoop->inGate())
        return armTimerAction(nullptr, &call, nullptr, nullptr, nullptr) ==
            kIOReturnSuccess ? 0 : EIO;
    const IOReturn result = session->gate->runAction(armTimerAction, &call);
    return result == kIOReturnSuccess ? 0 : EIO;
}

int startSingle(void *context, void *manager, const uint8_t *request,
                size_t requestSize) {
    auto *session = static_cast<Session *>(context);
    if (!session || !request || requestSize != S::SingleScanSize ||
        !session->workLoop || !session->gate || !session->workLoop->inGate() ||
        !session->controller || !session->interface || !session->manager ||
        manager != session->manager || isRetiring(*session) || isCleaned(*session) ||
        session->controller->isInactive() || session->interface->isInactive() ||
        session->interface->getProvider() != session->controller ||
        session->gate->getWorkLoop() != session->workLoop ||
        !eventRouter || !eventRouter->supportsInterface(
            session->interface, E::DriverKind::Broadcom43224) ||
        !globalAPI.eligible43224(globalAPI.context, session->controller,
                                 session->interface, session->manager)) return ENXIO;

    // The exact E8 at startScan+0x28 has a guarded scoped PID reader. The
    // retained proc token preserves the original proc_t reference; every use
    // also checks proc_exiting before relying on its PID for deferred work.
    if (ScanOwner::isExiting(session->owner)) return ESRCH;
    return ScanOwner::invoke(session->owner, verifiedStartScan, session->manager,
                             const_cast<uint8_t *>(request));
}

int snapshotCompleted(void *context, void *interface, void *manager) {
    auto *session = static_cast<Session *>(context);
    const bool aggregateActive = session && hasAggregate(*session);
    if (!session || !session->workLoop || !session->workLoop->inGate() ||
        interface != session->interface || manager != session->manager ||
        !aggregateActive || ScanOwner::isExiting(session->owner))
        return ESTALE;

    for (;;) {
        const uint8_t *result = nullptr;
        const int error = ScanOwner::invokeGetResult(
            session->owner, verifiedGetResult, manager, &result);
        if (error == 5) return 0; // Exact El Cap manager EOF return.
        if (error) return error;
        if (!result) return EIO;

        uint8_t fixed[ScanAggregate::RecordSize] {};
        uint8_t header[ScanBridge::KernelHeaderSize] {};
        memcpy(header, result, sizeof(header));
        int appendError = ScanAggregate::snapshotKernelResult(
            header, sizeof(header), fixed, sizeof(fixed));
        if (!appendError) {
            enterSpin(session->stateLock);
            appendError = session->aggregate.append(fixed, sizeof(fixed));
            leaveSpin(session->stateLock);
        }
        memset(header, 0, sizeof(header));
        memset(fixed, 0, sizeof(fixed));
        if (appendError) return appendError;
    }
}

void finishAggregate(void *context, int error) {
    auto *session = static_cast<Session *>(context);
    if (!session) return;
    enterSpin(session->stateLock);
    session->aggregate.finish(error);
    leaveSpin(session->stateLock);
}

void publishFinalEvent(void *context, void *interface, uint32_t eventCode) {
    auto *session = static_cast<Session *>(context);
    if (!session || !eventRouter || !eventRouter->publishManaged(interface, eventCode))
        reportFailure(nullptr, interface, EIO);
}

void reportFailure(void *, void *, int error) {
    SYSLOG("scan-sequence", "bounded scan queue stopped with errno %d", error);
}

void releaseOwner(Session &session) {
    proc_t process = nullptr;
    lockRegistry();
    process = session.owner.process;
    session.owner.process = nullptr;
    session.owner.pid = 0;
    unlockRegistry();
    if (process) proc_rele(process);
}

void releaseOwnerIfIdle(Session &session) {
    proc_t process = nullptr;
    lockRegistry();
    if (!isSubmitting(session) && !isCleaning(session) && !isCleaned(session) &&
        session.coordinator.state() == S::State::Idle && !hasAggregate(session)) {
        process = session.owner.process;
        session.owner.process = nullptr;
        session.owner.pid = 0;
    }
    unlockRegistry();
    if (process) proc_rele(process);
}

bool hasAggregate(Session &session) {
    enterSpin(session.stateLock);
    const bool active = session.aggregate.active();
    leaveSpin(session.stateLock);
    return active;
}

bool hasCancelledAggregate(Session &session) {
    enterSpin(session.stateLock);
    const bool cancelled = session.aggregate.error() == ECANCELED;
    leaveSpin(session.stateLock);
    return cancelled;
}

void finishOwnerCancellationIfIdle(Session &session) {
    lockRegistry();
    if (session.coordinator.state() == S::State::Idle &&
        session.ownerCancellation.ownerPending() && !isSubmitting(session) &&
        !isRetiring(session) && !isCleaning(session) && !isCleaned(session)) {
        // Keep the completed ECANCELED aggregate as a per-PID tombstone. The
        // old provider may still hold the cancelled child's PID-keyed results;
        // GET11 must not fall through to those partial results.
        session.ownerCancellation.completeOwner(
            session.ownerCancellation.ownerGeneration());
    }
    unlockRegistry();
}

void clearAggregate(Session &session) {
    enterSpin(session.stateLock);
    const auto detached = session.aggregate.clear();
    leaveSpin(session.stateLock);
    ScanAggregate::Store::destroy(detached);
}

S::API coordinatorAPI(Session &session) {
    S::API api;
    api.context = &session;
    api.lock = {&session.stateLock, enterLock, leaveLock};
    api.allocate = allocateJobs;
    api.deallocate = releaseJobs;
    api.runOnGate = runOnGate;
    api.schedule = schedule;
    api.startSingle = startSingle;
    api.snapshotCompleted = snapshotCompleted;
    api.finishAggregate = finishAggregate;
    api.publishFinalEvent = publishFinalEvent;
    api.reportFailure = reportFailure;
    return api;
}

Session *findByInterfaceLocked(void *interface, bool requireSetupReady = false) {
    for (size_t index = 0; index < MaximumSessions; ++index) {
        Session &session = sessions[index];
        if (session.used && !isCleaned(session) && session.interface == interface &&
            (!requireSetupReady || isSetupReady(session)))
            return &session;
    }
    return nullptr;
}

Session *findByTimer(IOTimerEventSource *timer) {
    if (!registryLock.lock || !timer) return nullptr;
    lockRegistry();
    Session *found = nullptr;
    for (size_t index = 0; index < MaximumSessions; ++index)
        if (sessions[index].used && isSetupReady(sessions[index]) &&
            sessions[index].timer == timer) {
            found = &sessions[index];
            break;
        }
    unlockRegistry();
    return found;
}

void enqueueCleanup(Session &session) {
    if (!registryLock.lock || !session.cleanupCall) return;
    lockRegistry();
    if (isCleaned(session) || isCleaning(session) || isSubmitting(session) ||
        __atomic_exchange_n(&session.cleanupQueued, 1U, __ATOMIC_ACQ_REL)) {
        unlockRegistry();
        return;
    }
    thread_call_enter(session.cleanupCall);
    unlockRegistry();
}

void timerFired(OSObject *, IOTimerEventSource *sender) {
    Session *session = findByTimer(sender);
    if (!session || !session->workLoop || !session->workLoop->inGate()) return;
    const S::Deferred callback = session->pending;
    void *owner = session->pendingOwner;
    const uint64_t generation = session->pendingGeneration;
    session->pending = nullptr;
    session->pendingOwner = nullptr;
    session->pendingGeneration = 0;
    if (callback) callback(owner, generation);
    finishOwnerCancellationIfIdle(*session);
    if (session->coordinator.state() == S::State::Idle) {
        releaseOwnerIfIdle(*session);
        if (isRetiring(*session)) enqueueCleanup(*session);
    }
}

IOReturn cancelAction(OSObject *, void *argument, void *, void *, void *) {
    auto *session = static_cast<Session *>(argument);
    if (!session || !session->workLoop || !session->workLoop->inGate())
        return kIOReturnNotReady;
    session->coordinator.cancel(session->interface);
    return kIOReturnSuccess;
}

struct CancelGenerationCall {
    Session *session = nullptr;
    uint64_t generation = 0;
};

IOReturn cancelGenerationAction(OSObject *, void *argument, void *, void *, void *) {
    auto *call = static_cast<CancelGenerationCall *>(argument);
    if (!call || !call->session || !call->session->workLoop ||
        !call->session->workLoop->inGate()) return kIOReturnNotReady;
    call->session->coordinator.cancelGeneration(call->session->interface,
                                                call->generation);
    return kIOReturnSuccess;
}

void cancelCallback(thread_call_param_t argument0, thread_call_param_t) {
    auto *session = static_cast<Session *>(argument0);
    if (!session || !session->gate || !session->workLoop) return;
    uint64_t generation = 0;
    bool cancelAll = false;
    lockRegistry();
    const bool claimed = session->ownerCancellation.claim(
        isSubmitting(*session), isRetiring(*session), &generation, &cancelAll);
    unlockRegistry();
    if (!claimed) return;

    if (cancelAll) {
        if (session->workLoop->inGate())
            (void)cancelAction(nullptr, session, nullptr, nullptr, nullptr);
        else
            (void)session->gate->runAction(cancelAction, session);
    } else if (generation) {
        CancelGenerationCall call {session, generation};
        if (session->workLoop->inGate())
            (void)cancelGenerationAction(nullptr, &call, nullptr, nullptr, nullptr);
        else
            (void)session->gate->runAction(cancelGenerationAction, &call);
    }
    if (!cancelAll) finishOwnerCancellationIfIdle(*session);
    if (session->coordinator.state() == S::State::Idle) {
        releaseOwnerIfIdle(*session);
        if (isRetiring(*session)) enqueueCleanup(*session);
    }
}

void enqueueCompletionLocked(Session &session, void *interface,
                             S::CompletionKind kind) {
    S::CompletionTicket ticket {};
    if (!session.coordinator.captureCompletionTicket(interface, &ticket)) return;
    if (session.completionRecords.enqueue(ticket, kind) && session.completionCall)
        thread_call_enter(session.completionCall);
}

IOReturn completionAction(OSObject *, void *argument, void *, void *, void *) {
    auto *session = static_cast<Session *>(argument);
    if (!session || !session->workLoop || !session->workLoop->inGate())
        return kIOReturnNotReady;
    S::CompletionRecord record {};
    lockRegistry();
    const bool hasRecord = session->completionRecords.pop(&record);
    unlockRegistry();
    if (!hasRecord) return kIOReturnSuccess;
    if (record.kind == S::CompletionKind::Failure) {
        session->coordinator.failCurrent(session->interface, EIO,
            record.ticket.generation, record.ticket.startToken);
    } else {
        session->coordinator.highLevelPostMessageReturned(
            session->interface, S::ScanDoneEvent,
            record.ticket.generation, record.ticket.startToken);
    }
    return kIOReturnSuccess;
}

void completionCallback(thread_call_param_t argument0, thread_call_param_t) {
    auto *session = static_cast<Session *>(argument0);
    if (!session || !session->gate || !session->workLoop) return;
    if (session->workLoop->inGate())
        (void)completionAction(nullptr, session, nullptr, nullptr, nullptr);
    else
        (void)session->gate->runAction(completionAction, session);
    finishOwnerCancellationIfIdle(*session);
    if (session->coordinator.state() == S::State::Idle) {
        releaseOwnerIfIdle(*session);
        if (isRetiring(*session)) enqueueCleanup(*session);
    }
    lockRegistry();
    if (session->completionRecords.pending() && !isCleaning(*session) &&
        !isCleaned(*session) && session->completionCall)
        thread_call_enter(session->completionCall);
    unlockRegistry();
}

IOReturn serviceInterest(void *, void *refCon, UInt32 messageType,
                         IOService *, void *, vm_size_t) {
    auto *session = static_cast<Session *>(refCon);
    if (!session || (messageType != kIOMessageServiceIsTerminated &&
                     messageType != kIOMessageServiceIsRequestingClose))
        return kIOReturnSuccess;
    lockRegistry();
    markRetiring(*session);
    if (session->cancelCall && !isSubmitting(*session) &&
        !isCleaning(*session) && !isCleaned(*session))
        thread_call_enter(session->cancelCall);
    unlockRegistry();
    return kIOReturnSuccess;
}

void cleanupCallback(thread_call_param_t argument0, thread_call_param_t) {
    auto *session = static_cast<Session *>(argument0);
    if (!session) return;
    thread_call_t call = session->cleanupCall;
    IOWorkLoop *loop = session->workLoop;
    if (!isRetiring(*session) || session->coordinator.state() != S::State::Idle ||
        (loop && loop->inGate())) {
        __atomic_store_n(&session->cleanupQueued, 0U, __ATOMIC_RELEASE);
        return;
    }
    lockRegistry();
    if (isSubmitting(*session) || isCleaning(*session) || isCleaned(*session)) {
        unlockRegistry();
        __atomic_store_n(&session->cleanupQueued, 0U, __ATOMIC_RELEASE);
        return;
    }
    __atomic_store_n(&session->cleaning, 1U, __ATOMIC_RELEASE);
    unlockRegistry();

    // Remove notifiers synchronously before draining thread calls; after these
    // return no termination callback may enqueue more work for this session.
    if (session->controllerNotifier) {
        session->controllerNotifier->remove();
        session->controllerNotifier = nullptr;
    }
    if (session->interfaceNotifier) {
        session->interfaceNotifier->remove();
        session->interfaceNotifier = nullptr;
    }
    if (session->cancelCall) (void)thread_call_cancel_wait(session->cancelCall);
    if (session->completionCall) (void)thread_call_cancel_wait(session->completionCall);

    // removeEventSource waits for the workloop to finish any timer or gate
    // callback. This worker is outside that workloop, so it cannot self-deadlock.
    if (session->timer) {
        session->timer->cancelTimeout();
        if (loop && session->timerAdded) (void)loop->removeEventSource(session->timer);
        session->timerAdded = false;
    }
    if (session->gate) {
        if (loop && session->gateAdded) (void)loop->removeEventSource(session->gate);
        session->gateAdded = false;
    }
    session->pending = nullptr;
    session->pendingOwner = nullptr;
    clearAggregate(*session);
    releaseOwner(*session);
    (void)call; // Bounded retired slots keep callback storage alive permanently.
    lockRegistry();
    session->ownerCancellation.clear();
    session->cancelledOwners.clear();
    session->completionRecords.clear();
    session->cancelledOwnerOverflow = false;
    __atomic_store_n(&session->cleaned, 1U, __ATOMIC_RELEASE);
    unlockRegistry();
}

IOReturn setupSession(Session &session, IOService *controller,
                      IOService *interface, OSObject *manager,
                      IOWorkLoop *loop) {
    if (!session.stateLock.lock) session.stateLock.lock = IOSimpleLockAlloc();
    if (!session.stateLock.lock) return kIOReturnNoMemory;
    if (!session.cleanupCall)
        session.cleanupCall = thread_call_allocate_with_priority(
            cleanupCallback, &session, THREAD_CALL_PRIORITY_KERNEL);
    if (!session.cleanupCall) return kIOReturnNoMemory;
    if (!session.cancelCall)
        session.cancelCall = thread_call_allocate_with_priority(
            cancelCallback, &session, THREAD_CALL_PRIORITY_KERNEL);
    if (!session.cancelCall) return kIOReturnNoMemory;
    if (!session.completionCall)
        session.completionCall = thread_call_allocate_with_priority(
            completionCallback, &session, THREAD_CALL_PRIORITY_KERNEL);
    if (!session.completionCall) return kIOReturnNoMemory;

    // These identity keys are reserved under registryLock before setup begins.
    // Do not rewrite them here: event hooks may already be looking up this
    // resident session while event sources and notifiers are being prepared.
    controller->retain();
    interface->retain();
    manager->retain();
    loop->retain();

    session.gate = IOCommandGate::commandGate(eventOwner);
    session.timer = IOTimerEventSource::timerEventSource(eventOwner, timerFired);
    if (!session.gate || !session.timer) return kIOReturnNoMemory;
    if (loop->addEventSource(session.gate) != kIOReturnSuccess)
        return kIOReturnNotReady;
    session.gateAdded = true;
    if (loop->addEventSource(session.timer) != kIOReturnSuccess)
        return kIOReturnNotReady;
    session.timerAdded = true;

    const auto seqAPI = coordinatorAPI(session);
    if (!session.coordinator.ready() && !session.coordinator.prepare(seqAPI))
        return kIOReturnNotReady;

    session.controllerNotifier = controller->registerInterest(
        gIOGeneralInterest, serviceInterest, nullptr, &session);
    session.interfaceNotifier = interface->registerInterest(
        gIOGeneralInterest, serviceInterest, nullptr, &session);
    if (!session.controllerNotifier || !session.interfaceNotifier)
        return kIOReturnNotReady;
    __atomic_store_n(&session.setupReady, 1U, __ATOMIC_RELEASE);
    return kIOReturnSuccess;
}

bool verifyProvider(KernelPatcher &patcher, size_t providerIndex,
                    mach_vm_address_t providerAddress, size_t providerSize,
                    const E::EventRouter &router) {
    E::ProviderSymbols symbols {};
    const E::LoadedImage image {
        reinterpret_cast<const uint8_t *>(providerAddress), providerSize};
    // EventRouter admitted the exact provider and symbols before installing
    // hooks. Re-reading its pinned entry bytes here would reject our own
    // detours; require that same immutable admission identity instead.
    return resolveProviderEvents(patcher, providerIndex, providerAddress,
                                 providerSize, symbols) &&
        router.hasActiveVerifiedProvider(image, symbols);
}

} // namespace

bool initialize(KernelPatcher &patcher, size_t providerIndex,
                mach_vm_address_t providerAddress, size_t providerSize,
                OSObject *owner, E::EventRouter &router, const API &api) {
    if (__atomic_load_n(&initialized, __ATOMIC_ACQUIRE) ||
        !providerAddress || !providerSize || !owner || !router.ready() ||
        !api.eligible43224) return false;
    if (!verifyProvider(patcher, providerIndex, providerAddress, providerSize,
                        router)) return false;
    StartScan start = nullptr;
    if (!verifyStartScan(patcher, providerIndex, providerAddress, providerSize, &start))
        return false;
    patcher.clearError();
    const uintptr_t getResult = patcher.solveSymbol(providerIndex,
        "__ZN18IO80211ScanManager13getScanResultEPP22apple80211_scan_result",
        providerAddress, providerSize);
    const bool getResultSolved = patcher.getError() == KernelPatcher::Error::NoError;
    patcher.clearError();
    if (!getResultSolved || !getResult || getResult >= providerAddress + providerSize)
        return false;
    if (!ScanOwner::ready() && !ScanOwner::install(
            patcher, providerIndex, providerAddress, providerSize)) return false;
    if (!ScanOwner::ready()) return false;

    registryLock.lock = IOSimpleLockAlloc();
    if (!registryLock.lock) return false;
    owner->retain();
    eventOwner = owner;
    eventRouter = &router;
    globalAPI = api;
    verifiedStartScan = start;
    verifiedGetResult = reinterpret_cast<ScanOwner::GetResult>(getResult);
    __atomic_store_n(&initialized, 1U, __ATOMIC_RELEASE);
    return true;
}

bool ready() {
    return __atomic_load_n(&initialized, __ATOMIC_ACQUIRE) && registryLock.lock &&
        eventOwner && eventRouter && verifiedStartScan && verifiedGetResult &&
        globalAPI.eligible43224 &&
        ScanOwner::ready() && eventRouter->ready();
}

int submit(IOService *controller, IOService *interface,
           const uint8_t *nativeRequest, size_t nativeSize) {
    if (!ready() || !controller || !interface || !nativeRequest) return ENXIO;
    if (controller->isInactive() || interface->isInactive() ||
        interface->getProvider() != controller) return ENXIO;
    if (!eventRouter->supportsInterface(interface, E::DriverKind::Broadcom43224))
        return EOPNOTSUPP;

    void *managerPointer = nullptr;
    memcpy(&managerPointer, reinterpret_cast<const uint8_t *>(interface) +
           ProviderContract::InterfaceScanManagerOffset, sizeof(managerPointer));
    auto *manager = static_cast<OSObject *>(managerPointer);
    IOWorkLoop *loop = controller->getWorkLoop();
    if (!manager || !loop || interface->getWorkLoop() != loop ||
        !globalAPI.eligible43224(globalAPI.context, controller, interface, manager))
        return EOPNOTSUPP;

    // Validate before touching a previous EOF/result set. This catches every
    // schema, count, and unmapped-tail rejection without changing GET11 state.
    const size_t validationSize = S::MaxJobs * S::SingleScanSize;
    auto *validation = static_cast<uint8_t *>(IOMallocZero(validationSize));
    if (!validation) return ENOMEM;
    uint32_t validatedCount = 0;
    const auto validationResult = S::build43224Plan(
        nativeRequest, nativeSize, validation, validationSize, &validatedCount);
    memset(validation, 0, validationSize);
    IOFree(validation, validationSize);
    if (validationResult.error) return validationResult.error;

    Session *session = nullptr;
    bool reserved = false;
    lockRegistry();
    for (size_t index = 0; index < MaximumSessions; ++index) {
        if (sessions[index].used && !isCleaned(sessions[index]) &&
            sessions[index].interface == interface) {
            session = &sessions[index];
            break;
        }
    }
    if (!session) {
        for (size_t index = 0; index < MaximumSessions; ++index) {
            if (!sessions[index].used) {
                session = &sessions[index];
                session->used = true;
                session->controller = controller;
                session->interface = interface;
                session->manager = manager;
                session->workLoop = loop;
                __atomic_store_n(&session->setupReady, 0U, __ATOMIC_RELEASE);
                __atomic_store_n(&session->retiring, 0U, __ATOMIC_RELEASE);
                __atomic_store_n(&session->cleaned, 0U, __ATOMIC_RELEASE);
                __atomic_store_n(&session->cleaning, 0U, __ATOMIC_RELEASE);
                __atomic_store_n(&session->cleanupQueued, 0U, __ATOMIC_RELEASE);
                session->ownerCancellation.clear();
                session->cancelledOwners.clear();
                session->completionRecords.clear();
                session->cancelledOwnerOverflow = false;
                reserved = true;
                break;
            }
        }
    }
    if (session && !reserved && (session->controller != controller ||
        session->manager != manager || session->workLoop != loop)) {
        unlockRegistry();
        return EOPNOTSUPP;
    }
    if (session && (isRetiring(*session) || isCleaned(*session) ||
                    isCleaning(*session) || isSubmitting(*session) ||
                    session->ownerCancellation.ownerPending() ||
                    session->cancelledOwnerOverflow)) {
        const bool overflow = session->cancelledOwnerOverflow;
        unlockRegistry();
        return overflow ? ENOSPC : EBUSY;
    }
    if (session) setSubmitting(*session, true);
    unlockRegistry();
    if (!session) return ENOSPC;

    if (reserved) {
        const IOReturn setup = setupSession(*session, controller, interface, manager, loop);
        if (setup != kIOReturnSuccess) {
            markRetiring(*session);
            lockRegistry();
            if (!session->cleanupCall) {
                __atomic_store_n(&session->cleaned, 1U, __ATOMIC_RELEASE);
            }
            setSubmitting(*session, false);
            unlockRegistry();
            if (session->cleanupCall) enqueueCleanup(*session);
            return setup == kIOReturnNoMemory ? ENOMEM : EOPNOTSUPP;
        }
    }

    if (isRetiring(*session)) {
        finishSubmitting(*session);
        return ENXIO;
    }

    if (session->coordinator.state() != S::State::Idle) {
        finishSubmitting(*session);
        return EBUSY;
    }

    enterSpin(session->stateLock);
    const bool resultLeased = session->aggregate.leased();
    leaveSpin(session->stateLock);
    if (resultLeased) {
        finishSubmitting(*session);
        return EBUSY;
    }

    // Capture first, then reserve space for this PID in case this sequence
    // later exits while a provider request node still contains child results.
    ScanOwner::Token nextOwner;
    if (!ScanOwner::capture(nextOwner)) {
        finishSubmitting(*session);
        return EOPNOTSUPP;
    }

    proc_t previousOwner = nullptr;
    lockRegistry();
    const bool ownerCanProceed = !isRetiring(*session) && !isCleaning(*session) &&
        !isCleaned(*session) && session->cancelledOwners.canAdd(nextOwner.pid);
    if (ownerCanProceed) {
        previousOwner = session->owner.process;
        session->owner.process = nextOwner.process;
        session->owner.pid = nextOwner.pid;
        nextOwner.process = nullptr;
        nextOwner.pid = 0;
    }
    unlockRegistry();
    if (!ownerCanProceed) {
        ScanOwner::release(nextOwner);
        finishSubmitting(*session);
        return isRetiring(*session) ? ENXIO : ENOSPC;
    }
    if (previousOwner) proc_rele(previousOwner);

    // A new SET86 replaces the previous managed result set. The old pool is
    // detached under the state spinlock and wiped/freed afterward.
    clearAggregate(*session);

    enterSpin(session->stateLock);
    const bool aggregateBegan = session->aggregate.begin(session->owner.pid);
    leaveSpin(session->stateLock);
    if (!aggregateBegan) {
        releaseOwner(*session);
        finishSubmitting(*session);
        return EBUSY;
    }
    auto *pool = static_cast<uint8_t *>(IOMallocZero(ScanAggregate::StorageSize));
    if (!pool) {
        clearAggregate(*session);
        releaseOwner(*session);
        finishSubmitting(*session);
        return ENOMEM;
    }
    enterSpin(session->stateLock);
    session->aggregate.setStorage(pool, {releaseJobs});
    leaveSpin(session->stateLock);

    bool firstProviderStartSucceeded = false;
    const int error = session->coordinator.submit(interface, manager,
        nativeRequest, nativeSize, &firstProviderStartSucceeded);
    lockRegistry();
    session->cancelledOwners.clearAfterSuccessfulFirstStart(
        session->owner.pid, aggregateBegan, firstProviderStartSucceeded);
    unlockRegistry();
    if (error && session->coordinator.state() == S::State::Idle) {
        clearAggregate(*session);
        releaseOwner(*session);
    }
    finishSubmitting(*session);
    return error;
}

bool shouldSuppress(void *, void *interface, uint32_t eventCode) {
    if (!ready() || !registryLock.lock || !interface) return false;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface, true);
    unlockRegistry();
    return session && session->coordinator.suppressExternalEvent(interface, eventCode);
}

void afterPost(void *, void *interface, uint32_t eventCode) {
    if (!ready() || !registryLock.lock || !interface || eventCode != S::ScanDoneEvent)
        return;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface, true);
    if (session && !isCleaning(*session) && !isCleaned(*session) &&
        session->completionCall)
        enqueueCompletionLocked(*session, interface, S::CompletionKind::Advance);
    unlockRegistry();
}

void eventContextViolation(void *, void *interface, uint32_t eventCode) {
    if (!ready() || !registryLock.lock || !interface ||
        (eventCode != S::ScanDoneEvent && eventCode != S::ScanManagerDoneEvent)) return;
    // This callback is restricted by EventRouter to an already-returned
    // original scan event in interrupt/interrupts-disabled context. All work
    // here is bounded atomic state, spin-lock lookup, and a preallocated call.
    lockRegistry();
    Session *session = findByInterfaceLocked(interface, true);
    if (session && !isCleaning(*session) && !isCleaned(*session) &&
        session->completionCall)
        enqueueCompletionLocked(*session, interface, S::CompletionKind::Failure);
    unlockRegistry();
}

void cancel(IOService *interface) {
    if (!ready() || !registryLock.lock || !interface) return;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface);
    if (session) {
        markRetiring(*session);
        if (!isSubmitting(*session) && !isCleaning(*session) &&
            !isCleaned(*session) && session->cancelCall)
            thread_call_enter(session->cancelCall);
    }
    unlockRegistry();
    if (!session) return;
}

bool peekManagedResult(IOService *controller, IOService *interface, int callerPID,
                       uint8_t *fixedOldResult, size_t resultSize,
                       uint64_t *token, int *error) {
    if (error) *error = EINVAL;
    if (token) *token = 0;
    if (!ready() || !controller || !interface || callerPID <= 0 || !token ||
        !error || resultSize != ScanAggregate::RecordSize || !fixedOldResult)
        return false;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface);
    if (session && session->controller != controller) {
        unlockRegistry();
        return false;
    }
    if (session && (isSubmitting(*session) || isCleaning(*session))) {
        unlockRegistry();
        *error = EBUSY;
        return true;
    }
    if (session && (session->cancelledOwnerOverflow ||
                    session->cancelledOwners.contains(callerPID))) {
        unlockRegistry();
        *error = ECANCELED;
        return true;
    }
    const bool cancellationPending = session &&
        session->ownerCancellation.ownerPending();
    if (session) setSubmitting(*session, true);
    unlockRegistry();
    if (!session) return false;

    enterSpin(session->stateLock);
    const int ownerPID = session->aggregate.ownerPID();
    const int aggregateError = session->aggregate.error();
    leaveSpin(session->stateLock);
    if (ownerPID <= 0) {
        finishSubmitting(*session);
        return false;
    }

    // An unrelated PID must not invalidate an exiting owner's aggregate.
    // The provider keys these result nodes by PID, so only that owner can
    // consume this managed state.
    if (callerPID != ownerPID) {
        finishSubmitting(*session);
        return false;
    }

    if (cancellationPending || aggregateError == ECANCELED) {
        *error = ECANCELED;
        finishSubmitting(*session);
        return true;
    }

    bool ownerExiting = false;
    lockRegistry();
    if (session->owner.pid == ownerPID && session->owner.process)
        ownerExiting = proc_exiting(session->owner.process) != 0;
    unlockRegistry();
    if (ownerExiting) {
        // Preserve a managed terminal error while the child request node may
        // still contain unaggregated results. The cancellation callback is
        // generation-bound; finishSubmitting() requeues it if its worker ran
        // early while this request held the session reservation.
        enterSpin(session->stateLock);
        session->aggregate.finish(ECANCELED);
        leaveSpin(session->stateLock);
        const uint64_t generation = session->coordinator.activeGeneration(interface);
        lockRegistry();
        if (!session->cancelledOwners.add(ownerPID))
            session->cancelledOwnerOverflow = true;
        const bool requested = session->ownerCancellation.requestOwner(generation);
        if (requested && session->cancelCall && !isCleaning(*session) &&
            !isCleaned(*session)) thread_call_enter(session->cancelCall);
        unlockRegistry();
        *error = ECANCELED;
        finishSubmitting(*session);
        return true;
    }

    bool managed = false;
    enterSpin(session->stateLock);
    *error = session->aggregate.peek(callerPID, fixedOldResult, resultSize,
                                     &managed, token);
    leaveSpin(session->stateLock);
    finishSubmitting(*session);
    return managed;
}

bool commitManagedResult(IOService *interface, int callerPID, uint64_t token,
                         bool copiedOut) {
    if (!ready() || !interface || callerPID <= 0 || !token) return false;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface, true);
    unlockRegistry();
    if (!session) return false;
    enterSpin(session->stateLock);
    const bool committed = session->aggregate.commit(callerPID, token, copiedOut);
    leaveSpin(session->stateLock);
    return committed;
}

int prepareAssociation(IOService *interface) {
    if (!ready() || !interface) return ENXIO;
    lockRegistry();
    Session *session = findByInterfaceLocked(interface);
    if (session && (isSubmitting(*session) || isCleaning(*session) ||
                    session->ownerCancellation.ownerPending())) {
        unlockRegistry();
        return EBUSY;
    }
    if (session) setSubmitting(*session, true);
    unlockRegistry();
    if (!session) return 0;
    if (session->coordinator.state() != S::State::Idle) {
        finishSubmitting(*session);
        return EBUSY;
    }
    enterSpin(session->stateLock);
    const bool resultLeased = session->aggregate.leased();
    leaveSpin(session->stateLock);
    if (resultLeased) {
        finishSubmitting(*session);
        return EBUSY;
    }
    // Preserve the cancelled owner's managed error until a new scan replaces
    // the provider's PID-keyed request node. Otherwise GET11 can fall through
    // and expose the final child scan that cancellation intentionally skipped.
    if (!hasCancelledAggregate(*session)) {
        clearAggregate(*session);
        releaseOwner(*session);
    }
    finishSubmitting(*session);
    return 0;
}

int checkBusy(IOService *interface) {
    if (!interface) return ENXIO;
    // No sequence can be active before initialization has published its
    // callbacks and registry. Unknown/non-admitted drivers retain native
    // behavior; this helper is only installed with the verified sequence API.
    if (!__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return 0;
    if (!registryLock.lock) return 0;

    lockRegistry();
    Session *session = findByInterfaceLocked(interface);
    if (!session) {
        unlockRegistry();
        return 0;
    }
    if (isSubmitting(*session) || isRetiring(*session) || isCleaning(*session) ||
        isCleaned(*session) || session->ownerCancellation.ownerPending()) {
        unlockRegistry();
        return EBUSY;
    }
    // Hold a temporary admission reservation while reading the gate-owned
    // coordinator and aggregate state. Cleanup and a competing submit both
    // honor this flag. The native original still must run on the same gate,
    // which closes the gap between this observation and its handler.
    setSubmitting(*session, true);
    unlockRegistry();

    int error = 0;
    if (session->coordinator.state() != S::State::Idle) {
        error = EBUSY;
    } else {
        enterSpin(session->stateLock);
        const bool resultLeased = session->aggregate.leased();
        leaveSpin(session->stateLock);
        if (resultLeased) error = EBUSY;
    }
    finishSubmitting(*session);
    return error;
}

int invalidateResults(IOService *interface) {
    if (!interface) return ENXIO;
    if (!__atomic_load_n(&initialized, __ATOMIC_ACQUIRE)) return 0;
    if (!registryLock.lock) return 0;

    lockRegistry();
    Session *session = findByInterfaceLocked(interface);
    if (!session) {
        unlockRegistry();
        return 0;
    }
    if (isSubmitting(*session) || isRetiring(*session) || isCleaning(*session) ||
        isCleaned(*session) || session->ownerCancellation.ownerPending()) {
        unlockRegistry();
        return EBUSY;
    }
    // Keep cleanup and another request from changing this session while the
    // state and result lease are checked. Runtime calls this only after a
    // successful native handler, synchronously on the same manager gate.
    setSubmitting(*session, true);
    unlockRegistry();

    int error = 0;
    if (session->coordinator.state() != S::State::Idle) {
        error = EBUSY;
    } else {
        enterSpin(session->stateLock);
        const bool resultLeased = session->aggregate.leased();
        leaveSpin(session->stateLock);
        if (resultLeased) error = EBUSY;
    }
    if (!error && !hasCancelledAggregate(*session)) {
        clearAggregate(*session);
        releaseOwner(*session);
    }
    finishSubmitting(*session);
    return error;
}

} // namespace ScanSequenceKernel
} // namespace LegacyWiFi
