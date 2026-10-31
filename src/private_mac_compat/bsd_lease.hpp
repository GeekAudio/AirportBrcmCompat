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
#include "ifnet_scope_core.hpp"

namespace PrivateMAC { namespace BSDLease {
class RootScope;
class CallbackScope;

class CallbackPin {
    friend class Scope;
    friend class RootScope;
    friend class CallbackScope;
    friend bool held(IOService *,IOService *,ifnet_t,uint64_t *);
    uintptr_t returnPC=0;
    int (*runtimeBuild)()=nullptr;
    IOLock *registry=nullptr;
    bool publicKPI=false;
    IfnetScopeCore::Registry scopeCore;
public:
    constexpr CallbackPin()
        : returnPC(0),runtimeBuild(nullptr),registry(nullptr),publicKPI(false),
          scopeCore() {}
    // Lifetime: one plugin instance, no reconfiguration. Only a plan returned
    // by the complete acquire/callback/release ABI contract can authorize a
    // synchronous borrowed-ifnet scope; kernel UUID/build labels are not input.
    int prepare(const KernelContracts::IfnetIoctlPlan &contract,
                int (*checkRuntimeBuild)());
    // Call only after the integration layer has independently admitted the
    // complete public ifnet_ioctl -> fixed driver callback contract. This
    // selects a separate mode; it does not itself validate callback provenance.
    int preparePublicKPI(int (*checkRuntimeBuild)());
};

class RootScope {
    friend class CallbackScope;
    friend class Scope;
    void leave();
    CallbackPin *pin_=nullptr;
    uintptr_t owner_=0;
    IfnetScopeCore::Tuple tuple_;
    IfnetScopeCore::RootTicket ticket_;
    RootScope *next_=nullptr;
public:
    RootScope()=default;
    ~RootScope();
    RootScope(const RootScope &)=delete;
    RootScope &operator=(const RootScope &)=delete;
    RootScope(RootScope &&)=delete;
    RootScope &operator=(RootScope &&)=delete;
    // Captures only opaque arguments. No argument memory or ifnet fields are
    // read by this outer public-KPI scope.
    int enter(CallbackPin &,ifnet_t,uintptr_t protocol,uintptr_t command,
              void *data);
};

class CallbackScope {
    friend class Scope;
    void leave();
    CallbackPin *pin_=nullptr;
    uintptr_t owner_=0;
    IfnetScopeCore::Tuple tuple_;
    IfnetScopeCore::CallbackTicket ticket_;
    CallbackScope *next_=nullptr;
public:
    CallbackScope()=default;
    ~CallbackScope();
    CallbackScope(const CallbackScope &)=delete;
    CallbackScope &operator=(const CallbackScope &)=delete;
    CallbackScope(CallbackScope &&)=delete;
    CallbackScope &operator=(CallbackScope &&)=delete;
    // The protocol is inherited from the same-thread public root; the other
    // callback arguments must match that root exactly.
    int enter(CallbackPin &,ifnet_t,uintptr_t command,void *data);
};

class Scope {
    friend bool held(IOService *,IOService *,ifnet_t,uint64_t *);
    friend class RootScope;
    friend class CallbackScope;
    CallbackPin *pin=nullptr;
    IOService *controller=nullptr,*primary=nullptr;
    ifnet_t borrowed=nullptr;
    uintptr_t owner=0;
    uint64_t generation=0;
    bool publicKPI=false;
    IfnetScopeCore::Tuple tuple;
    IfnetScopeCore::PerformTicket performTicket;
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
    // Called only by the existing performCommand wrapper inside the admitted
    // fixed callback. The perform ticket is claimed before driver identity
    // checks; a failed check never creates a held Scope.
    int enterScoped(CallbackPin &,IOService *controller,IOService *primary,
                    ifnet_t originalIfp,uintptr_t command,void *data);
};
// Optional ifp==nullptr is for pre-lookup checks only. A StationSession must
// receive the original callback's exact ifp and prove it remains leased.
bool held(IOService *controller,IOService *primary,ifnet_t expectedIfp,
          uint64_t *generation=nullptr);
uintptr_t registryOwner();
} } // namespace PrivateMAC::BSDLease
#endif
