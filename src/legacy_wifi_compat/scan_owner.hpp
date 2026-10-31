// Exact-callsite process owner capture for ElCap ScanManager request nodes.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_OWNER_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_OWNER_HPP

#include <Headers/kern_patcher.hpp>
#include <IOKit/IOLocks.h>
#include <kern/thread.h>
#include <sys/proc.h>
#include "scan_owner_core.hpp"

namespace LegacyWiFi {
namespace ScanOwner {

using StartScan = int (*)(void *manager, const uint8_t *request);
using GetResult = int (*)(void *manager, const uint8_t **result);

struct Token {
    proc_t process = nullptr; // proc_self() reference retained until release().
    int pid = 0;
    Token() = default;
    Token(const Token &) = delete;
    Token &operator=(const Token &) = delete;
};

// Rewrites only the verified E8 at ElCap ScanManager::startScan+0x28. The
// replacement returns the retained request owner's PID only for an active
// same-thread scope; every other call uses the saved original proc_selfpid.
bool install(KernelPatcher &, size_t providerIndex,
             mach_vm_address_t providerAddress, size_t providerSize);
bool ready();

bool capture(Token &);
bool isExiting(const Token &);
void release(Token &);
int invoke(Token &, StartScan, void *manager, const uint8_t *request);
int invokeGetResult(Token &, GetResult, void *manager, const uint8_t **result);

} // namespace ScanOwner
} // namespace LegacyWiFi

#endif
