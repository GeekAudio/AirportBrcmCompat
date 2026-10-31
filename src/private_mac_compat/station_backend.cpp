#include "station_backend.hpp"
#include "../scan_kernel/primary_interface_iokit.hpp"
#include <kern/thread.h>
#include <sys/kauth.h>
#include "root_credential.hpp"

namespace PrivateMAC {
namespace {
uintptr_t thisThread() { return reinterpret_cast<uintptr_t>(current_thread()); }
bool exactClass(const IOService *object,const char *name) {
    return object && object->getMetaClass() && !strcmp(object->getMetaClass()->getClassName(),name);
}
bool propertyAddress(IOService *service,const uint8_t *expected) {
    OSObject *object=service->copyProperty("IOMACAddress");
    if (!object) return false;
    const auto *data=OSDynamicCast(OSData,object);
    const bool equal=data && data->getLength()==6 &&
        (!expected || !memcmp(data->getBytesNoCopy(),expected,6));
    object->release();return equal;
}
} // namespace
StationSession::~StationSession() {
    opened=false;
    if (desiredData) desiredData->release();
    if (loop) loop->release();
    if (primary) primary->release();
    if (controller) controller->release();
    memset(request.address,0,sizeof(request.address));
}
int StationSession::identity() const {
    if (!opened || thisThread()!=thread || !controller || !primary || !loop || !bsd)
        return ENXIO;
    uint64_t generation=0;
    const int lease=bindings.lifecycleLease(controller,primary,bsd,&generation);if (lease) return lease;
    if (!generation || generation!=leaseGeneration) return ESTALE;
    if (controller->isInactive() || primary->isInactive() || primary->getProvider()!=controller)
        return ENXIO;
    if (controller->getWorkLoop()!=loop || !loop->inGate()) return EDEADLK;
    if (ifnet_softc(bsd)!=primary ||
        !PrimaryInterface::propertyMatchesIfnet(primary,ifnet_name(bsd),ifnet_unit(bsd))) return ENXIO;
    if (bindings.runtimeBuild()) return EOPNOTSUPP;
    return 0;
}
int StationSession::open(const StationBindings &b,IOService *c,IOService *i,ifnet_t originalIfp,
                         const NativeRequest &plan,
                         const AuthData *auth,uint32_t upper,uintptr_t caller,uintptr_t expectedCaller) {
    if (controller || primary || loop || bsd || opened) return EBUSY;
    if (!b.setHardwareAddress || !b.getHardwareAddress || !b.iovar || !b.getState ||
        !b.strictIdle || !b.registryOwner || !b.runtimeBuild || !b.lifecycleLease) return EINVAL;
    if (!expectedCaller || caller!=expectedCaller || !auth || auth->version!=1 ||
        auth->lower!=1 || !supportedStationAuthUpper(upper) || auth->upper!=upper) return EOPNOTSUPP;
    if (!c || !i || !originalIfp || !plan.requested || !privateShape(plan.address)) return EINVAL;
    if (!currentCredentialIsRoot()) return EACCES;
    if (b.runtimeBuild()) return EOPNOTSUPP;
    uint64_t generation=0;
    const int lease=b.lifecycleLease(c,i,originalIfp,&generation);if (lease) return lease;
    if (!generation) return ESTALE;
    if (!exactClass(c,"AirPort_BrcmNIC") || !exactClass(i,"AirPort_BrcmNIC_Interface") ||
        c->isInactive() || i->isInactive() || i->getProvider()!=c) return ENXIO;
    if (b.registryOwner()==thisThread()) return EDEADLK;
    IOWorkLoop *candidate=c->getWorkLoop();
    if (!candidate || !candidate->inGate()) return EDEADLK;
    // BSD is the exact handle borrowed from this synchronous callback. The
    // lifecycle lease above is the lifetime proof; no name lookup or normal
    // ifnet reference is used to substitute for it.
    controller=c;controller->retain();primary=i;primary->retain();loop=candidate;loop->retain();
    bindings=b;request=plan;thread=thisThread();leaseGeneration=generation;bsd=originalIfp;
    if (ifnet_softc(bsd)!=primary ||
        !PrimaryInterface::propertyMatchesIfnet(primary,ifnet_name(bsd),ifnet_unit(bsd))) return ENXIO;
    uint8_t currentBSD[6] {};
    int error=ifnet_lladdr_copy_bytes(bsd,currentBSD,6);
    lastBackendStatus=static_cast<uint32_t>(error);
    if (error) return error;
    if (!propertyAddress(primary,nullptr)) return EIO;
    desiredData=OSData::withBytes(request.address,6);
    if (!desiredData) return ENOMEM;
    opened=true;
    error=identity();
    if (!error) error=unassociated(this);
    if (error) opened=false;
    return error;
}
API StationSession::api() {
    API result;
    if (!opened) return result;
    result.context=this;result.authorization=authorization;result.registryUnlocked=registryUnlocked;
    result.controllerGate=controllerGate;result.unassociated=unassociated;result.policySource=policySource;
    result.setFirmware=setFirmware;result.verifyDriverCache=verifyDriverCache;
    result.setPrimaryBSD=setPrimaryBSD;result.verifyPrimaryBSD=verifyPrimaryBSD;
    result.publishCurrentIOMAC=publishCurrentIOMAC;result.verifyCurrentIOMAC=verifyCurrentIOMAC;
    return result;
}
int StationSession::authorization(void *p) {
    const auto *s=static_cast<StationSession *>(p);
    const int error=s->identity();if (error) return error;
    return currentCredentialIsRoot()?0:EACCES;
}
int StationSession::registryUnlocked(void *p) {
    const auto *s=static_cast<StationSession *>(p);
    return s->bindings.registryOwner()==thisThread()?EDEADLK:0;
}
int StationSession::controllerGate(void *p) { return static_cast<StationSession *>(p)->identity(); }
int StationSession::unassociated(void *p) {
    auto *s=static_cast<StationSession *>(p);
    int error=s->identity();if (error) return error;
    uint32_t state[2] {};
    error=s->bindings.getState(s->controller,s->primary,state);
    if (error) {s->lastBackendStatus=static_cast<uint32_t>(error);return EIO;}
    if (state[0]!=1 || state[1]!=0) return EBUSY;
    // STATE0 alone does not establish idle. The exact pinned backend checks
    // main station/infrastructure role, association FSM, scan and pending join.
    return s->bindings.strictIdle(s->controller,s->primary);
}
int StationSession::policySource(void *p,const uint8_t *address) {
    const auto *s=static_cast<StationSession *>(p);
    return s->request.requested && address && !memcmp(address,s->request.address,6)?0:EOPNOTSUPP;
}
int StationSession::setFirmware(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);
    const uint32_t status=s->bindings.setHardwareAddress(s->controller,address);
    s->lastBackendStatus=status;
    return status?EIO:0; // IOReturn is not errno; preserve raw status separately.
}
int StationSession::verifyDriverCache(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);uint8_t current[6] {},bss[6] {};
    uint32_t status=s->bindings.getHardwareAddress(s->controller,current);
    s->lastBackendStatus=status;
    if (status || memcmp(current,address,6)) return EIO;
    const int32_t result=s->bindings.iovar(s->controller,"cur_etheraddr",nullptr,0,bss,6,false,nullptr);
    s->lastBackendStatus=static_cast<uint32_t>(result);
    // These are two driver SOFTWARE caches; neither establishes RF identity.
    return result || memcmp(bss,address,6)?EIO:0;
}
int StationSession::setPrimaryBSD(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);
    const int error=ifnet_set_lladdr(s->bsd,address,6);
    s->lastBackendStatus=static_cast<uint32_t>(error);return error;
}
int StationSession::verifyPrimaryBSD(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);uint8_t current[6] {};
    const int error=ifnet_lladdr_copy_bytes(s->bsd,current,6);
    s->lastBackendStatus=static_cast<uint32_t>(error);
    return error?error:(memcmp(current,address,6)?EIO:0);
}
int StationSession::publishCurrentIOMAC(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);
    if (!s->desiredData || s->desiredData->getLength()!=6 ||
        memcmp(s->desiredData->getBytesNoCopy(),address,6)) return EINVAL;
    return s->primary->setProperty("IOMACAddress",s->desiredData)?0:ENOMEM;
}
int StationSession::verifyCurrentIOMAC(void *p,const uint8_t *address) {
    auto *s=static_cast<StationSession *>(p);return propertyAddress(s->primary,address)?0:EIO;
}
} // namespace PrivateMAC
