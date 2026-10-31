#include "scan_owner.hpp"
#include <sys/errno.h>
#include <string.h>

namespace LegacyWiFi {
namespace ScanOwner {
namespace {

constexpr uintptr_t StartScanProcSelfPIDCall = 0x61610;
constexpr uintptr_t StartScanEntry = 0x615e8;
constexpr uintptr_t GetResultProcSelfPIDCall = 0x61b46;
constexpr uintptr_t GetResultEntry = 0x61b1e;
constexpr const char *ProcSelfPIDSymbol = "_proc_selfpid";
constexpr const char *StartScanSymbol =
    "__ZN18IO80211ScanManager9startScanEP20apple80211_scan_data";
constexpr const char *GetResultSymbol =
    "__ZN18IO80211ScanManager13getScanResultEPP22apple80211_scan_result";

using ProcSelfPID = int (*)();
ProcSelfPID originalProcSelfPID = nullptr;
struct ScopeLock {
    IOSimpleLock *lock = nullptr;
    IOInterruptState interruptState = 0;
};
ScopeLock scopeLock {};
Core::Registry scopes;
uint32_t didInstall = 0;
uintptr_t pinnedReturnAddresses[2] {};

__attribute__((noinline)) int routedProcSelfPID() {
    const int original = originalProcSelfPID ? originalProcSelfPID() : 0;
    const uintptr_t caller = reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (caller != pinnedReturnAddresses[0] &&
        caller != pinnedReturnAddresses[1]) return original;
    const auto thread = reinterpret_cast<uintptr_t>(current_thread());
    return scopes.pidForThread(thread, original);
}

bool inRange(size_t size, size_t offset, size_t count) {
    return offset <= size && count <= size - offset;
}

bool relativeTarget(const uint8_t *image, size_t size, size_t callOffset,
                    uintptr_t base, uintptr_t *target) {
    if (!image || !target || !inRange(size, callOffset, 5) ||
        image[callOffset] != 0xe8 || base > UINTPTR_MAX - callOffset - 5)
        return false;
    int32_t relative = 0;
    memcpy(&relative, image + callOffset + 1, sizeof(relative));
    const uintptr_t next = base + callOffset + 5;
    return Core::addRelative32(next, relative, target);
}

} // namespace

bool install(KernelPatcher &patcher, size_t providerIndex,
             mach_vm_address_t providerAddress, size_t providerSize) {
    if (__atomic_load_n(&didInstall, __ATOMIC_ACQUIRE)) return false;
    if (!providerAddress || providerSize > UINTPTR_MAX - providerAddress) return false;
    const auto *image = reinterpret_cast<const uint8_t *>(providerAddress);
    const uint8_t startPrefix[] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,
        0x53,0x48,0x81,0xec,0xb8,0x00,0x00,0x00,0x48,0x89,0xf3,0x49,0x89,0xfe
    };
    const uint8_t resultPrefix[] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,
        0x53,0x48,0x81,0xec,0x98,0x00,0x00,0x00,0x49,0x89,0xf4,0x49,0x89,0xfd
    };
    if (!inRange(providerSize, StartScanEntry, sizeof(startPrefix)) ||
        memcmp(image + StartScanEntry, startPrefix, sizeof(startPrefix)) ||
        !inRange(providerSize, StartScanProcSelfPIDCall, 5) ||
        !inRange(providerSize, GetResultEntry, sizeof(resultPrefix)) ||
        memcmp(image + GetResultEntry, resultPrefix, sizeof(resultPrefix)) ||
        !inRange(providerSize, GetResultProcSelfPIDCall, 5)) return false;

    patcher.clearError();
    const uintptr_t original = patcher.solveSymbol(KernelPatcher::KernelID,
                                                   ProcSelfPIDSymbol);
    const uintptr_t loadedEntry = patcher.solveSymbol(providerIndex, StartScanSymbol,
        providerAddress, providerSize);
    const uintptr_t getResultEntry = patcher.solveSymbol(providerIndex, GetResultSymbol,
        providerAddress, providerSize);
    const bool resolved = patcher.getError() == KernelPatcher::Error::NoError;
    patcher.clearError();
    uintptr_t originalCallTarget = 0;
    if (!resolved || !original || loadedEntry != providerAddress + StartScanEntry ||
        getResultEntry != providerAddress + GetResultEntry ||
        !relativeTarget(image, providerSize, StartScanProcSelfPIDCall,
                        providerAddress, &originalCallTarget) ||
        originalCallTarget != original ||
        !relativeTarget(image, providerSize, GetResultProcSelfPIDCall,
                        providerAddress, &originalCallTarget) ||
        originalCallTarget != original) return false;

    const uintptr_t destination = reinterpret_cast<uintptr_t>(&routedProcSelfPID);
    const uintptr_t sites[] = {providerAddress + StartScanProcSelfPIDCall,
                               providerAddress + GetResultProcSelfPIDCall};
    int32_t rel32[2] {};
    for (size_t i = 0; i < 2; ++i)
        if (sites[i] > UINTPTR_MAX - 5 ||
            !Core::relative32(sites[i] + 5, destination, &rel32[i])) return false;

    scopeLock.lock = IOSimpleLockAlloc();
    if (!scopeLock.lock) return false;
    if (!scopes.prepare({&scopeLock,
        [](void *p) {
            auto *lock = static_cast<ScopeLock *>(p);
            lock->interruptState = IOSimpleLockLockDisableInterrupt(lock->lock);
        },
        [](void *p) {
            auto *lock = static_cast<ScopeLock *>(p);
            IOSimpleLockUnlockEnableInterrupt(lock->lock, lock->interruptState);
        }})) return false;
    originalProcSelfPID = reinterpret_cast<ProcSelfPID>(original);
    pinnedReturnAddresses[0] = sites[0] + 5;
    pinnedReturnAddresses[1] = sites[1] + 5;

    for (size_t i = 0; i < 2; ++i) {
        uint8_t patch[5] = {0xe8,0,0,0,0};
        memcpy(patch + 1, &rel32[i], sizeof(rel32[i]));
        patcher.clearError();
        (void)patcher.routeBlock(sites[i], patch, sizeof(patch), false, true);
        const bool routed = patcher.getError() == KernelPatcher::Error::NoError;
        patcher.clearError();
        uintptr_t routedTarget = 0;
        if (!routed || !relativeTarget(image, providerSize,
            i == 0 ? StartScanProcSelfPIDCall : GetResultProcSelfPIDCall,
            providerAddress, &routedTarget) || routedTarget != destination)
            return false;
    }
    __atomic_store_n(&didInstall, 1U, __ATOMIC_RELEASE);
    return true;
}

bool ready() {
    return __atomic_load_n(&didInstall, __ATOMIC_ACQUIRE) &&
        originalProcSelfPID && scopeLock.lock && scopes.ready();
}

bool capture(Token &token) {
    if (!ready() || token.process) return false;
    proc_t process = proc_self();
    if (!process) return false;
    if (proc_exiting(process)) {
        proc_rele(process);
        return false;
    }
    const int pid = proc_pid(process);
    if (pid <= 0) {
        proc_rele(process);
        return false;
    }
    token.process = process;
    token.pid = pid;
    return true;
}

bool isExiting(const Token &token) {
    return !token.process || token.pid <= 0 || proc_exiting(token.process) != 0;
}

void release(Token &token) {
    proc_t process = token.process;
    token.process = nullptr;
    token.pid = 0;
    if (process) proc_rele(process);
}

int invoke(Token &owner, StartScan startScan, void *manager, const uint8_t *request) {
    if (!ready() || !startScan || !manager || !request || isExiting(owner))
        return ESRCH;
    Core::Scope scope;
    const auto thread = reinterpret_cast<uintptr_t>(current_thread());
    if (!scopes.enter(scope, thread, owner.process, owner.pid)) return EBUSY;
    const int result = startScan(manager, request);
    (void)scopes.leave(scope);
    return result;
}

int invokeGetResult(Token &owner, GetResult getResult, void *manager,
                    const uint8_t **result) {
    if (!ready() || !getResult || !manager || !result || isExiting(owner))
        return ESRCH;
    Core::Scope scope;
    const auto thread = reinterpret_cast<uintptr_t>(current_thread());
    if (!scopes.enter(scope, thread, owner.process, owner.pid)) return EBUSY;
    const int error = getResult(manager, result);
    (void)scopes.leave(scope);
    return error;
}

} // namespace ScanOwner
} // namespace LegacyWiFi
