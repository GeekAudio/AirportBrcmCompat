// Unwired real typed GET43 component. No IOUserClient, routes or production build.
#ifndef AIRPORT_AWDL_DRIVER_VERSION_BACKEND_HPP
#define AIRPORT_AWDL_DRIVER_VERSION_BACKEND_HPP
#include "driver_version_format.hpp"
#include <IOKit/IOService.h>
#include <mach/mach_types.h>

namespace AWDLKernel {
enum class VersionPinStatus : uint32_t { Passed=0, Input, MachO, UUID, Code, Guard };
class DriverVersionBackend final {
    using GetVersion=int32_t (*)(void *,void *,LegacyVersion *);
    using GetRole=uint32_t (*)(void *);
    using GetBSDName=const char *(*)(void *);
    const uint8_t *brcm=nullptr,*legacy=nullptr;
    size_t brcmSize=0,legacySize=0;
    GetVersion getVersion=nullptr;
    GetRole getRole=nullptr;
    GetBSDName getBSDName=nullptr;
    bool validPins() const;
    bool identity(IOService *,IOService *) const;
public:
    DriverVersionBackend()=default;
    DriverVersionBackend(const DriverVersionBackend &)=delete;
    DriverVersionBackend &operator=(const DriverVersionBackend &)=delete;
    // Both headers must come from the genuine live image owners, with readable
    // mapped extents and a lifetime excluding unload. This parser neither probes
    // VM nor proves a caller-supplied address is mapped. Initialize before use,
    // serialized by the owner; no arbitrary function pointer can be supplied.
    // Any failure clears this binding. No controller/provider/task is cached.
    VersionPinStatus initialize(const void *brcmImage,size_t brcmExtent,
                                const void *legacyImage,size_t legacyExtent);
    // Identity only for an already authorized event session, under the same
    // retained controller/provider and original captured WorkLoop exclusion.
    // Rechecks live pins, real class/topology/role6/awdl0. This is not task
    // authorization, a stop lease, or an assertion that an event pipe is ready.
    bool matchesProviderIdentity(IOService *controller,IOService *provider) const;
    // Caller owns/retains currentTask, controller, provider and image lifetimes
    // for this synchronous call and provides genuine kernel IOUC buffers. A
    // retain is not a stop-exclusion lease: the integration owner must exclude
    // provider teardown while holding this same original controller WorkLoop
    // gate. This component acquires no deferred lease and never drops the gate.
    // Exact original classes/provider relationship, role6 and pinned awdl0 name
    // plus actual task entitlements are checked here; no root/bool substitutes.
    VersionResult get43(task_t currentTask,IOService *controller,IOService *provider,
                        const VersionCall &) const;
};
} // namespace AWDLKernel
#endif
