#ifndef AIRPORT_AWDL_SCOPED_RESET_HPP
#define AIRPORT_AWDL_SCOPED_RESET_HPP
#include "client_registry.hpp"
#include <Headers/kern_patcher.hpp>
namespace AWDLKernel { namespace ScopedResetBridge {
// Startup only, before any independent client is created. Registry and module
// storage must have static lifetime. This supplies no event-pipe capability.
bool install(KernelPatcher &,ClientRegistry &,size_t legacyIndex,
             mach_vm_address_t legacyAddress,size_t legacySize);
bool ready();
// Only a Pending/Closing client genuinely reserved by this module's factory.
// Start failure does not justify calling stop on an unattached old object.
void resetFailedStart(IOUserClient *);
// Numeric, pointer-free outcomes for boot diagnostics.
uint32_t completed();
uint32_t closedWithoutCallback();
uint32_t retired();
} }
#endif
