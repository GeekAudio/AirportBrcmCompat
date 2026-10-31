// Runtime symbol admission for the two retained legacy Broadcom child
// binaries. This proves the pre-route byte/UUID/import contract only; it does
// not grant pointer-read authority or establish runtime Wi-Fi support.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_ADMISSION_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_ADMISSION_HPP

#include "disassociate_child_contracts.hpp"

#include <Headers/kern_patcher.hpp>

#include <stddef.h>
#include <stdint.h>

namespace LegacyWiFi { namespace DisassociateAdmission {

namespace DCC = DisassociateChildContract;

// A successful Admission is immutable through this API. It binds the exact
// pre-route mapped image, UUID, child kind, kinfo index, and resolved symbols.
// Callers should retain this object and use its original addresses when
// installing routes; do not re-verify the image after detouring it.
struct Admission {
    bool ready;
    DCC::ChildKind child;
    size_t index;
    DCC::P::Image image;
    uint8_t imageUUID[16];
    DCC::SymbolAddresses symbols;
    DCC::ImportAddresses imports;
    DCC::RouteSymbolAddresses routeSymbols;

    Admission();
};

// Performs only static image/symbol admission. On failure, an empty output is
// left behind. If out already contains a successful Admission, the call is
// rejected without modifying it. This function never installs routes.
bool verifyChild(KernelPatcher &patcher, size_t index, uintptr_t base,
                 size_t size, DCC::ChildKind child, Admission *out);

} } // namespace LegacyWiFi::DisassociateAdmission

#endif
