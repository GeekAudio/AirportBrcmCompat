// IOKit/workloop adapter for the bounded El Capitan SET86 -> SET11 sequence.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_SEQUENCE_KERNEL_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_SEQUENCE_KERNEL_HPP

#include <Headers/kern_patcher.hpp>
#include <IOKit/IOService.h>
#include "event_router.hpp"
#include "scan_owner.hpp"
#include "scan_aggregate.hpp"

namespace LegacyWiFi {
namespace ScanSequenceKernel {

using StartScan = int (*)(void *manager, const uint8_t *request);

// The owner-PID callback is mandatory. ElCap ScanManager keys request and
// result nodes by proc_selfpid(); deferred children must use the PID captured
// from the original SET86 caller. The callback must establish a narrowly
// scoped owner-PID context around the verified startScan call. Missing owner
// context means SET86 splitting is unavailable.
struct API {
    void *context = nullptr;
    bool (*eligible43224)(void *context, IOService *controller,
                          IOService *interface, void *manager) = nullptr;
};

// Resolve and guard the pinned provider's ScanManager::startScan entry plus
// the exact SET10/error-cleanup calls in its body. EventRouter must already be
// ready and admitted for the 43224 driver image.
bool initialize(KernelPatcher &, size_t providerIndex,
                mach_vm_address_t providerAddress, size_t providerSize,
                OSObject *eventOwner, EventContracts::EventRouter &,
                const API &);
bool ready();

// Called by the native SET86 runtime after copyIn and shape validation. The
// adapter captures the caller PID before entering the WorkLoop gate.
int submit(IOService *controller, IOService *interface,
           const uint8_t *nativeRequest, size_t nativeSize);

// Runtime GET11 peek/commit callbacks. A true peek return means this
// interface/PID owns the result (including Pending and persistent EOF).
// Successful peeks return a token; commit(true) advances only after native
// conversion and copyOut succeed. commit(false) releases the lease unchanged.
bool peekManagedResult(IOService *controller, IOService *interface, int callerPID,
                       uint8_t *fixedOldResult, size_t resultSize,
                       uint64_t *token, int *error);
bool commitManagedResult(IOService *interface, int callerPID, uint64_t token,
                         bool copiedOut);

// Association cannot overlap an in-flight split scan. An idle accepted
// association invalidates prior managed GET11 snapshots before the driver is
// invoked.
int prepareAssociation(IOService *interface);

// Read-only admission check for native El Cap SET10/SET86/SET20 paths that
// the old provider accepts but the compatibility bridge does not convert.
// The caller must run the check and the original handler on the same manager
// WorkLoop gate so a split scan cannot start between them. This check never
// clears managed GET11 results.
int checkBusy(IOService *interface);

// Called after a direct old-provider request returns success. It invalidates
// the previous managed GET11 result set and releases its retained PID owner.
// The caller must run it before leaving the manager WorkLoop gate.
int invalidateResults(IOService *interface);

// These exact signatures are suitable for EventContracts::RouterAPI. The
// router always calls original postMessage; suppression is at the BSD helper
// edge, and completion advances only after its cache/manager side effects.
bool shouldSuppress(void *context, void *interface, uint32_t eventCode);
void afterPost(void *context, void *interface, uint32_t eventCode);
// IRQ-only router notification when the original completion ran but its
// mirrored event could not safely be routed from that context.
void eventContextViolation(void *context, void *interface, uint32_t eventCode);

// Called by the provider/controller watcher on termination. References are
// released only after cancellation and any accepted code-10 event has drained.
void cancel(IOService *interface);

} // namespace ScanSequenceKernel
} // namespace LegacyWiFi

#endif
