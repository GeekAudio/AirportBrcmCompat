#include "disassociate_config.hpp"

#include <IOKit/IORegistryEntry.h>
#include <IOKit/IOService.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>

#include <stdint.h>
#include <string.h>

namespace {

constexpr char UseOLYHALDriverBootArg[] = "wlan.pcie.useOLYHALDriver";
constexpr char EnhancedDisassociationBootArg[] =
    "wlan.debug.EEparams.enhancedDisAssociationInfo";
constexpr char EnterpriseParametersKey[] = "wlan.enterprise.params";

IOService *selectProvisioningRoot(IOService *controller) {
    uint32_t useOLYHALDriver = 1;
    uint32_t parsedValue = 0;
    if (PE_parse_boot_argn(UseOLYHALDriverBootArg, &parsedValue,
                           sizeof(parsedValue))) {
        useOLYHALDriver = parsedValue;
    }

    // Tahoe's PCIe source selection uses the interface itself for value 1;
    // other parsed values select its provider. A missing argument keeps the
    // local default of 1.
    return useOLYHALDriver == 1 ? controller : controller->getProvider();
}

bool readPropertyBit(IOService *root, bool *bit) {
    if (!root || !bit) return false;

    // SearchProperty's kIOServiceSearchPropertyParents flag (1) maps to
    // both IORegistry parent traversal bits. Do not pass 1 directly here:
    // IORegistry's bit 1 means recursive child traversal.
    constexpr IOOptionBits ParentSearchOptions =
        kIORegistryIterateParents | kIORegistryIterateRecursively;

#if defined(IOKIT_ENABLE_SHARED_PTR)
    auto property = root->copyProperty(EnterpriseParametersKey,
                                      gIOServicePlane,
                                      ParentSearchOptions);
    OSData *data = OSDynamicCast(OSData, property.get());
#else
    OSObject *property = root->copyProperty(EnterpriseParametersKey,
                                            gIOServicePlane,
                                            ParentSearchOptions);
    OSData *data = OSDynamicCast(OSData, property);
#endif

    bool enabled = false;
    if (data) {
        const void *bytes = data->getBytesNoCopy(0, sizeof(uint32_t));
        if (bytes) {
            uint32_t word = 0;
            memcpy(&word, bytes, sizeof(word));
            enabled = (word & 1U) != 0;
        }
    }

#if !defined(IOKIT_ENABLE_SHARED_PTR)
    if (property) property->release();
#endif

    // A missing, mistyped, or short property means a false base value. The
    // caller still applies the independent native debug boot-argument
    // override after this property stage.
    *bit = enabled;
    return true;
}

} // namespace

namespace LegacyWiFi {
namespace DisassociateConfig {

bool read(IOService *controller, bool *enabled) {
    if (!controller || !enabled) return false;

    IOService *root = selectProvisioningRoot(controller);
    if (!root) return false;

    bool effectiveBit = false;
    if (!readPropertyBit(root, &effectiveBit)) return false;

    uint8_t parsedOverride = 0;
    if (PE_parse_boot_argn(EnhancedDisassociationBootArg, &parsedOverride,
                           sizeof(parsedOverride))) {
        effectiveBit = (parsedOverride & 1U) != 0;
    }

    *enabled = effectiveBit;
    return true;
}

} // namespace DisassociateConfig
} // namespace LegacyWiFi
