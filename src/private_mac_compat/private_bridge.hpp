#ifndef AIRPORT_BRCM_PRIVATE_BRIDGE_HPP
#define AIRPORT_BRCM_PRIVATE_BRIDGE_HPP
#include <Headers/kern_patcher.hpp>
#include "../scan_kernel/association_compat.hpp"

namespace PrivateBridge {
struct Install {
    size_t legacyIndex,brcmIndex;
    mach_vm_address_t legacyAddress,brcmAddress;
    size_t legacySize,brcmSize;
    AssociationCompat::Registry *associations;
    uintptr_t (*associationLockOwner)();
    int (*runtimeBuild)();
};
// Called only after pinned kernel/provider/legacy and scan/association routing.
// Partial routes keep their original trampolines but never enable private plans.
void install(KernelPatcher &,const Install &);
int entryAllowed(void *controller,void *primary);
bool available(void *controller,void *primary);
}
#endif
