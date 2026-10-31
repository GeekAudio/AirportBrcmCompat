// A borrowed synchronous BSD callback scope, not a newly acquired I/O ref.
// No route, initialization, kernel patch or hardware operation is registered.
#ifndef SKYWALK_PRIVATE_MAC_BSD_LEASE_HPP
#define SKYWALK_PRIVATE_MAC_BSD_LEASE_HPP
#include <stdint.h>
#include <stddef.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLocks.h>
#include <net/kpi_interface.h>
#include "../scan_kernel/kernel_contracts.hpp"

namespace PrivateMAC { namespace BSDLease {
class CallbackPin {
    friend class Scope;
    friend bool held(IOService *,IOService *,ifnet_t,uint64_t *);
    uintptr_t returnPC=0;
    int (*runtimeBuild)()=nullptr;
    IOLock *registry=nullptr;
public:
    // Lifetime: one plugin instance, no reconfiguration. Only a plan returned
    // by the complete acquire/callback/release ABI contract can authorize a
    // synchronous borrowed-ifnet scope; kernel UUID/build labels are not input.
    int prepare(const KernelContracts::IfnetIoctlPlan &contract,
                int (*checkRuntimeBuild)());
};
class Scope {
    friend bool held(IOService *,IOService *,ifnet_t,uint64_t *);
    CallbackPin *pin=nullptr;
    IOService *controller=nullptr,*primary=nullptr;
    ifnet_t borrowed=nullptr;
    uintptr_t owner=0;
    uint64_t generation=0;
    Scope *next=nullptr;
public:
    Scope()=default;
    ~Scope();
    Scope(const Scope &)=delete;
    Scope &operator=(const Scope &)=delete;
    // Only the ACTUAL performCommand replacement entry may capture returnPC
    // with __builtin_return_address(0) and pass it here. Calling this helper from
    // a worker, user-client or a synthetic direct invocation is not permitted.
    // Keep Scope on that same stack around the entire original performCommand.
    int enter(CallbackPin &,uintptr_t capturedReturnPC,IOService *controller,
              IOService *primary,ifnet_t originalIfp);
};
// Optional ifp==nullptr is for pre-lookup checks only. Once a Session has found
// en1, it MUST pass its handle and prove exact equality to the original ifp.
bool held(IOService *controller,IOService *primary,ifnet_t expectedIfp,
          uint64_t *generation=nullptr);
uintptr_t registryOwner();
} } // namespace PrivateMAC::BSDLease
#endif
