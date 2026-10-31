// Real kernel adapter under development. Not registered, loaded or installed.
#ifndef SKYWALK_PRIVATE_MAC_STATION_BACKEND_HPP
#define SKYWALK_PRIVATE_MAC_STATION_BACKEND_HPP
#include "transaction.hpp"
#include "native_request.hpp"
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSData.h>
#include <net/kpi_interface.h>

namespace PrivateMAC {
struct AuthData { uint32_t version,lower,upper; };
struct StationBindings {
    // Supplied only after UUID, range, bytes and exact auth caller validation.
    uint32_t (*setHardwareAddress)(void *,const uint8_t *)=nullptr;
    uint32_t (*getHardwareAddress)(void *,uint8_t *)=nullptr;
    int32_t (*iovar)(void *,const char *,void *,uint64_t,void *,uint64_t,bool,void *)=nullptr;
    int32_t (*getState)(void *,void *,uint32_t *)=nullptr;
    // Read-only pinned main-role / BSS / FSM / scan checks, all under old gate.
    // Returns errno, never an unmapped driver/IOReturn status.
    int (*strictIdle)(void *,void *)=nullptr;
    // Current thread owning registry lock, zero if none. Not 'lock is free'.
    uintptr_t (*registryOwner)()=nullptr;
    int (*runtimeBuild)()=nullptr;
    // Mandatory real lifetime/stop exclusion lease. A retained IOService,
    // isInactive()==false and nonnull wlc fields do NOT supply this proof.
    // The optional third argument is the retained BSD handle. A nonnull value
    // must be exactly the original callback's borrowed ifp, not just same name.
    // On success also reports the exact nonzero callback generation.
    int (*lifecycleLease)(void *,void *,ifnet_t,uint64_t *generation)=nullptr;
};
class StationSession {
    StationBindings bindings {};
    IOService *controller=nullptr,*primary=nullptr;
    IOWorkLoop *loop=nullptr;
    ifnet_t bsd=nullptr;
    OSData *desiredData=nullptr;
    NativeRequest request {};
    uintptr_t thread=0;
    uint64_t leaseGeneration=0;
    bool opened=false;
    int identity() const;
    static int authorization(void *);
    static int registryUnlocked(void *);
    static int controllerGate(void *);
    static int unassociated(void *);
    static int policySource(void *,const uint8_t *);
    static int setFirmware(void *,const uint8_t *);
    static int verifyDriverCache(void *,const uint8_t *);
    static int setPrimaryBSD(void *,const uint8_t *);
    static int verifyPrimaryBSD(void *,const uint8_t *);
    static int publishCurrentIOMAC(void *,const uint8_t *);
    static int verifyCurrentIOMAC(void *,const uint8_t *);
public:
    // Status is raw backend status only: never an address or kernel pointer.
    uint32_t lastBackendStatus=0;
    StationSession()=default;
    // Must stay on the synchronous gated ioctl stack, within the caller's real
    // lifecycle lease. Retains are references, not permission to defer to a
    // worker or survive provider stop/rebuild. No operation is done at unload.
    ~StationSession();
    StationSession(const StationSession &)=delete;
    StationSession &operator=(const StationSession &)=delete;
    int open(const StationBindings &,IOService *,IOService *,const NativeRequest &,
             const AuthData *,uint32_t expectedUpper,uintptr_t caller,uintptr_t expectedCaller);
    API api();
};
} // namespace PrivateMAC
#endif
