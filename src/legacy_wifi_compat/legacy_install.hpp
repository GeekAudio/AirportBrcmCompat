#ifndef AIRPORT_BRCM_LEGACY_WIFI_INSTALL_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_INSTALL_HPP
#include <Headers/kern_patcher.hpp>
namespace LegacyWiFi { namespace Installer {
enum class ImageKind { Provider, Broadcom4331, Broadcom43224 };
// Register only images delivered by the existing loaded-kext observer. This
// module never loads a kext or modifies a filesystem or userspace process.
void observe(KernelPatcher &, ImageKind, size_t index,
             mach_vm_address_t address, size_t size);
void kernelReady(KernelPatcher &);
} }
#endif
