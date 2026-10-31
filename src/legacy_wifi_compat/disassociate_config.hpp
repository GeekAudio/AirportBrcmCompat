// Read the reason-IE capability from the selected provisioning service.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_CONFIG_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_CONFIG_HPP

class IOService;

namespace LegacyWiFi {
namespace DisassociateConfig {

// Returns true when controller and the selected property root are valid and
// an effective bit was computed. A missing, mistyped, or short property is a
// valid disabled default; the enhanced-disassociation boot argument may
// still override that default. False means controller/output/root is invalid
// and leaves *enabled unchanged.
//
// Call from a safe thread while the caller's controller/WorkLoop lifetime
// contract is held. This function does not mutate registry properties or
// boot arguments.
bool read(IOService *controller, bool *enabled);

} // namespace DisassociateConfig
} // namespace LegacyWiFi

#endif
