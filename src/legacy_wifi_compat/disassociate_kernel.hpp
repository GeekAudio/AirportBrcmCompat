// Synchronous observation of the fixed legacy children's native SET22 path.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_KERNEL_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_KERNEL_HPP

#include "disassociate_admission.hpp"
#include "legacy_bridge.hpp"
#include "network_identity.hpp"

namespace LegacyWiFi { namespace DisassociateKernel {
using Source = NetworkIdentity::Source;
struct API {
    Source (*classify)(void *controller, void *interface) = nullptr;
    uintptr_t (*currentThread)() = nullptr;
    void *(*allocate)(size_t) = nullptr;
    void (*deallocate)(void *, size_t) = nullptr;
    // True means the configuration was read from the bridge's explicit native
    // property/boot-argument source. Absence of this callback is unknown, not
    // a disabled feature. The output is consumed only when this returns true.
    bool (*enhancedReasonConfiguration)(void *controller, bool *enabled) = nullptr;
};

bool initialize(const API &);
// Admission must have been collected before routing these child entries.
// A partial installation keeps each saved original callable and never enables
// metadata handling. This module does not invoke a private child worker itself.
// The mutation fence protects bridge reads. Native driver functions retain
// their original locking and execution order; the caller still needs the
// admitted synchronous controller WorkLoop gate.
bool installChild(KernelPatcher &, const DisassociateAdmission::Admission &);
bool ready(Source);

// The request adapter supplies already copied metadata and retains its request
// reservation. The original request stays unchanged. A nonzero result after
// the original call can mean disconnect happened but its requested cache flush
// could not be completed; it must never be converted to success by the caller.
// A separately observed gated primary-STA idle branch preserves the original
// setter's local cleanup and returns success without frame/cache actions, as
// the sampled native LINK_DOWN/event4 action does. It is not inferred from a
// missing worker or from a zero BSSID, and does not claim a cache flush occurred.
int perform(LegacyBridge::Handler original, void *controller, void *interface,
            void *virtualInterface, LegacyBridge::Request *, bool user64,
            uint32_t reason, uint32_t flush);
} }
#endif
