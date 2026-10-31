// Synchronous, EFI-only private station address bridge. Original PID/auth/key
// handlers remain in control. No user SET writes, factory fallback or worker.
#include "private_bridge.hpp"
#include "pinned_driver.hpp"
#include "bsd_lease.hpp"
#include "station_backend.hpp"
#include "state_gate.hpp"
#include "admission.hpp"
#include "../scan_kernel/diagnostics.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#include <IOKit/IOLib.h>
#include <kern/thread.h>
#include <sys/kauth.h>
#include "root_credential.hpp"

namespace PrivateBridge {
namespace {
constexpr const char *Perform="__ZN16IO80211Interface14performCommandEP19IONetworkControllermPvS2_";
constexpr const char *Associate="__ZN15AirPort_BrcmNIC12setASSOCIATEEP8OSObjectP21apple80211_assoc_data";
constexpr const char *Auth="__ZN15AirPort_BrcmNIC12setAUTH_TYPEEP8OSObjectP24apple80211_authtype_data";
using PerformCommand=int (*)(IOService *,IOService *,uint64_t,void *,void *);
PerformCommand originalPerform=nullptr;
PrivateMAC::DriverPins pins {};
PrivateMAC::DriverPins::SetAssociate originalAssociate=nullptr;
PrivateMAC::DriverPins::SetAuthType originalAuth=nullptr;
PrivateMAC::BSDLease::CallbackPin callbackPin;
Install config {};
IOLock *bridgeLock=nullptr;
uintptr_t lockOwner=0;
bool attempted=false,ready=false;
volatile unsigned privateSuccesses=0;
uintptr_t thread() {return reinterpret_cast<uintptr_t>(current_thread());}
void lock() {IOLockLock(bridgeLock);__atomic_store_n(&lockOwner,thread(),__ATOMIC_RELEASE);}
void unlock() {__atomic_store_n(&lockOwner,uintptr_t(0),__ATOMIC_RELEASE);IOLockUnlock(bridgeLock);}
bool enabled() {return __atomic_load_n(&ready,__ATOMIC_ACQUIRE);}
bool exactClass(const IOService *object,const char *name) {
    return object && object->getMetaClass() && !strcmp(object->getMetaClass()->getClassName(),name);
}
bool primaryPair(IOService *c,IOService *i) {
    return exactClass(c,"AirPort_BrcmNIC") && exactClass(i,"AirPort_BrcmNIC_Interface");
}
uintptr_t registryOwner() {
    const uintptr_t current=thread();
    if (__atomic_load_n(&lockOwner,__ATOMIC_ACQUIRE)==current ||
        PrivateMAC::BSDLease::registryOwner()==current ||
        (config.associationLockOwner && config.associationLockOwner()==current)) return current;
    return 0;
}
struct ControllerRecord {
    IOService *controller,*primary;
    PrivateMAC::Binding binding;
    PrivateMAC::Admission admission;
    PrivateMAC::State state {};
    ControllerRecord(IOService *c,IOService *i):controller(c),primary(i),
        binding{reinterpret_cast<uintptr_t>(c),reinterpret_cast<uintptr_t>(i),1},admission(binding) {
        c->retain();i->retain();
    }
    ~ControllerRecord() {primary->release();controller->release();}
    static void *operator new(size_t size) noexcept {return IOMallocZero(size);}
    static void operator delete(void *value,size_t size) noexcept {IOFree(value,size);}
};
// One retained primary object generation per boot. An actual detach/rebuild is
// refused; it must not inherit another controller's old plan or quarantine.
ControllerRecord *record=nullptr;
ControllerRecord *getRecord(IOService *c,IOService *i,bool create) {
    lock();ControllerRecord *found=record;unlock();
    if (!found && create) {
        auto *candidate=new ControllerRecord(c,i);
        if (!candidate) return nullptr;
        lock();if (!record) {record=candidate;candidate=nullptr;}found=record;unlock();
        delete candidate;
    }
    return found && found->controller==c && found->primary==i?found:nullptr;
}
struct Context {
    IOService *controller,*primary;
    ifnet_t ifp;
    ControllerRecord *record;
    PrivateMAC::AdmissionLease admission;
    uintptr_t owner;
    uint64_t generation;
    bool nativeShape;
    Context *next=nullptr;
};
Context *contexts=nullptr;
Context *findContext(void *c,void *i) {
    if (!bridgeLock || registryOwner()==thread()) return nullptr;
    Context *found=nullptr;const uintptr_t current=thread();
    lock();for (auto *p=contexts;p;p=p->next) if (p->owner==current && p->controller==c && p->primary==i) {
        found=p;break;
    }
    unlock();return found; // Only the actual current owner uses this stack pointer.
}
void add(Context &context) {lock();context.next=contexts;contexts=&context;unlock();}
void remove(Context &context) {
    lock();for (auto **p=&contexts;*p;p=&(*p)->next) if (*p==&context) {*p=context.next;break;}
    context.next=nullptr;unlock();
}
bool contextLive(Context *p,ifnet_t expected=nullptr) {
    if (!p || p->owner!=thread() || !enabled() || config.runtimeBuild() ||
        (expected && expected!=p->ifp)) return false;
    uint64_t generation=0;
    return PrivateMAC::BSDLease::held(p->controller,p->primary,p->ifp,&generation) &&
        generation==p->generation && !p->record->admission.isQuarantined();
}
int lifecycle(void *c,void *i,ifnet_t ifp,uint64_t *generation) {
    if (generation) *generation=0;
    if (registryOwner()==thread()) return EDEADLK;
    Context *p=findContext(c,i);
    if (!contextLive(p,ifp)) return ESTALE;
    if (generation) *generation=p->generation;
    return 0;
}
void quarantine(Context &p) {
    if (p.record->state.quarantined) {
        p.record->admission.poison(p.admission,thread(),static_cast<uint32_t>(p.record->state.firstFailure));
        ScanDiagnostics::record(ScanDiagnostics::PrivateQuarantined,1);
    }
}
bool gateHeld(IOService *c) {auto *loop=c->getWorkLoop();return loop && loop->inGate();}

bool statePins(void *) {return enabled() && pins.findBssCfg && pins.assocInProgress && !config.runtimeBuild();}
bool stateRoot(void *) {return PrivateMAC::currentCredentialIsRoot();}
bool stateLife(void *v,uintptr_t c,uintptr_t i) {
    auto *p=static_cast<Context *>(v);
    return p->controller==reinterpret_cast<void *>(c) && p->primary==reinterpret_cast<void *>(i) && contextLive(p);
}
bool stateGate(void *v,uintptr_t c) {
    auto *p=static_cast<Context *>(v);return p->controller==reinterpret_cast<void *>(c) && gateHeld(p->controller);
}
bool stateIdentity(void *v,uintptr_t c,uintptr_t i) {
    auto *p=static_cast<Context *>(v);
    return p->controller==reinterpret_cast<void *>(c) && p->primary==reinterpret_cast<void *>(i) &&
        primaryPair(p->controller,p->primary) && !p->controller->isInactive() && !p->primary->isInactive() &&
        p->primary->getProvider()==p->controller;
}
bool stateUnlocked(void *) {return registryOwner()!=thread();}
bool readState(void *,PrivateMAC::StateGate::Object kind,uintptr_t object,size_t extent,
               size_t offset,void *out,size_t size) {
    using namespace PrivateMAC::StateGate;
    const size_t bounds[]={controllerSize,wlcSize,pubSize,tableSize,modulePrefix,mainPrefix,
                           assocSize,scanPubSize,scanPrivateSize};
    const auto index=static_cast<unsigned>(kind);
    if (index>=sizeof(bounds)/sizeof(bounds[0]) || extent!=bounds[index] || !out ||
        object>>48!=0xffff || !validPointer(object,extent) || offset>extent || size>extent-offset) return false;
    // These are owner-derived objects under the real original BSD lifetime and
    // controller gate, not addresses received in an external SET payload.
    memcpy(out,reinterpret_cast<const void *>(object+offset),size);return true;
}
bool mainGetter(void *,uintptr_t c,uintptr_t *out) {
    if (!out) return false;*out=reinterpret_cast<uintptr_t>(pins.findBssCfg(reinterpret_cast<void *>(c),nullptr));
    return *out!=0;
}
bool assocProgress(void *,uintptr_t wlc,bool *out) {
    if (!out) return false;*out=pins.assocInProgress(reinterpret_cast<void *>(wlc));return true;
}
bool getState(void *,uintptr_t c,uintptr_t i,uint32_t out[2]) {
    const int32_t result=pins.getState(reinterpret_cast<void *>(c),reinterpret_cast<void *>(i),out);
    ScanDiagnostics::record(ScanDiagnostics::PrivateBackendStatus,result);return result==0;
}
bool infrastructureJoin(void *,uintptr_t,uintptr_t);
int inspectIdle(void *c,void *i,bool beforeAssociation) {
    using namespace PrivateMAC::StateGate;
    Context *p=findContext(c,i);if (!contextLive(p)) return ESTALE;
    Access access;access.context=p;access.pins=statePins;access.root=stateRoot;access.liveLease=stateLife;
    access.gateHeld=stateGate;access.identity=stateIdentity;access.registryUnlocked=stateUnlocked;
    access.read=readState;access.mainGetter=mainGetter;access.assocInProgress=assocProgress;access.getState=getState;
    access.infrastructureJoin=infrastructureJoin;
    Observation observation;
    const auto result=check(access,reinterpret_cast<uintptr_t>(c),reinterpret_cast<uintptr_t>(i),&observation);
    using namespace ScanDiagnostics;
    const Entry entries[] = {
        {PrivateGateReason,static_cast<int32_t>(result.reason)},
        {PrivateGateField,static_cast<int32_t>(result.field)},
        {PrivateGatePhase,beforeAssociation?0:1},
        {PrivateGateObservedMask,observation.reached},
        {PrivateGateMainLow16,static_cast<int32_t>(observation.mainUp | (uint32_t(observation.mainEnable)<<8))},
        {PrivateGateMainHigh16,static_cast<int32_t>(observation.mainAP | (uint32_t(observation.mainAssociated)<<8))},
        {PrivateGateMainRole,static_cast<int32_t>(observation.mainInfra | (uint32_t(static_cast<uint8_t>(observation.mainIndex))<<8))},
        {PrivateGateAssocLow16,static_cast<int32_t>(observation.assocState&0xffffU)},
        {PrivateGateAssocHigh16,static_cast<int32_t>(observation.assocState>>16)},
        {PrivateGateScan,observation.scanInProgress}
    };
    recordBatch(entries,sizeof(entries)/sizeof(entries[0]));
    if (result.ok()) return 0;
    if (result.field==Field::Authorization) return EACCES;
    return result.reason==Reason::ValueMismatch?EBUSY:EIO;
}
int strictIdle(void *c,void *i) {return inspectIdle(c,i,false);}
PrivateMAC::StationBindings bindings() {
    PrivateMAC::StationBindings b;
    b.setHardwareAddress=pins.setHardwareAddress;b.getHardwareAddress=pins.getHardwareAddress;
    b.iovar=pins.iovar;b.getState=pins.getState;b.strictIdle=strictIdle;b.registryOwner=registryOwner;
    b.runtimeBuild=config.runtimeBuild;b.lifecycleLease=lifecycle;return b;
}
struct DriverFrame {
    Context *context;
    AssociationCompat::Scope *scope;
    PrivateMAC::StationSession session;
    bool authAttempted=false,applied=false;
    DriverFrame(Context *c,AssociationCompat::Scope *s):context(c),scope(s) {}
};
bool infrastructureJoin(void *value,uintptr_t c,uintptr_t i) {
    auto *context=static_cast<Context *>(value);
    if (!contextLive(context) || !context->nativeShape || registryOwner()==thread() ||
        reinterpret_cast<uintptr_t>(context->controller)!=c ||
        reinterpret_cast<uintptr_t>(context->primary)!=i) return false;
    auto *scope=config.associations->find(thread(),context->controller,context->primary);
    if (!scope || !AssociationCompat::infrastructureIntent(*scope,thread(),
            context->controller,context->primary)) return false;
    if (scope->privateFrame) {
        const auto *frame=static_cast<const DriverFrame *>(scope->privateFrame);
        if (frame->context!=context || frame->scope!=scope || !frame->authAttempted) return false;
    }
    return contextLive(context);
}

int wrappedAuth(void *c,void *i,const PrivateMAC::AuthData *auth) {
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (!enabled()) return originalAuth(c,i,auth);
    if (registryOwner()==thread()) return EDEADLK;
    Context *context=findContext(c,i);
    auto *scope=config.associations->find(thread(),c,i);
    if (!scope || !scope->privatePlan.requested) return originalAuth(c,i,auth);
    auto *frame=static_cast<DriverFrame *>(scope->privateFrame);
    if (!contextLive(context) || !scope->consumed || !frame || frame->context!=context ||
        frame->scope!=scope || frame->authAttempted || caller!=pins.authCallerReturn) return EOPNOTSUPP;
    frame->authAttempted=true;
    // This is permission to disclose a DHCP device type, not address validity.
    // The legacy stack has no GET552; IPConfiguration's proven error fallback
    // keeps effective permission false. Do not manufacture native support.
    ScanDiagnostics::record(ScanDiagnostics::PrivateDhcpAllowedRequest,
                            scope->privatePlan.deviceTypeInDhcpAllowed?1:0);
    int error=frame->session.open(bindings(),context->controller,context->primary,scope->privatePlan,
                                   auth,scope->authUpper,caller,pins.authCallerReturn);
    if (!error) {
        auto api=frame->session.api();
        const auto result=PrivateMAC::apply(api,context->record->state,scope->privatePlan.address,true);
        ScanDiagnostics::record(ScanDiagnostics::PrivateApplyStage,static_cast<int32_t>(result.stage));
        error=result.error;
        frame->applied=!error && result.consistentPrivate;
        scope->privateApplied=frame->applied;
    }
    scope->privateError=error;
    ScanDiagnostics::record(ScanDiagnostics::PrivateApplyResult,error);
    ScanDiagnostics::record(ScanDiagnostics::PrivateBackendStatus,static_cast<int32_t>(frame->session.lastBackendStatus));
    quarantine(*context);
    if (error) return error;
    if (__sync_fetch_and_add(&privateSuccesses,1)==0) ScanDiagnostics::record(ScanDiagnostics::FirstPrivateApplied,0);
    return originalAuth(c,i,auth); // Preserve original auth and all caller error handling.
}
int wrappedDriverAssociate(void *c,void *i,const void *legacy) {
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (!enabled() || !primaryPair(static_cast<IOService *>(c),static_cast<IOService *>(i)))
        return originalAssociate(c,i,legacy);
    Context *context=findContext(c,i);
    if (!contextLive(context) || !gateHeld(context->controller)) return EOPNOTSUPP;
    auto *scope=config.associations->find(thread(),c,i);
    if (!scope) return context->nativeShape?EIO:originalAssociate(c,i,legacy);
    if (!scope->privatePlan.requested) return originalAssociate(c,i,legacy);
    if (!scope->consumed || scope->privateFrame || !legacy || caller!=pins.associateCallerReturn ||
        memcmp(legacy,scope->legacy,AssociationCompat::LegacySize)) return EINVAL;
    AssociationCompat::DriverValidationLease validation(*scope);
    if (!validation.acquired()) return EBUSY;
    if (scope->privatePlan.colocatedScopeUnsupported) {
        // Old default link events are a supported fallback only for an idle,
        // disconnected join. Never call any original association code first,
        // and never claim native grouping / current-scope GET387 support.
        const int idle=inspectIdle(c,i,true);
        ScanDiagnostics::record(ScanDiagnostics::ColocatedScopeFallbackGuard,idle);
        if (idle) return idle;
    }
    DriverFrame frame(context,scope);scope->privateFrame=&frame;
    int error=originalAssociate(c,i,legacy);
    if (frame.applied) {
        auto api=frame.session.api();
        const auto result=PrivateMAC::associationReturned(api,context->record->state,error,scope->consumed);
        error=result.error;scope->privateCompleted=result.consistentPrivate && !result.quarantined;
        ScanDiagnostics::record(ScanDiagnostics::PrivatePostResult,error);
        ScanDiagnostics::record(ScanDiagnostics::PrivateBackendStatus,static_cast<int32_t>(frame.session.lastBackendStatus));
        quarantine(*context);
    } else if (!error) error=scope->privateError?scope->privateError:EIO;
    scope->privateError=error;scope->privateFrame=nullptr;
    return error; // Session dies inside the original controller gate / BSD scope.
}
int wrappedPerform(IOService *i,IOService *c,uint64_t command,void *arg0,void *arg1) {
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    // Both 32/64-bit main SET20 entries share admission. Do not read a 40-byte
    // Request from the 32-byte form; only the common type/length DWORDs here.
    const bool set=command==0x802869c8ULL || command==0x802069c8ULL;
    if (!enabled() || !set || !arg1 || !primaryPair(c,i) ||
        ScanCompat::read32(static_cast<const uint8_t *>(arg1)+16)!=20) return originalPerform(i,c,command,arg0,arg1);
    PrivateMAC::BSDLease::Scope lease;
    int error=lease.enter(callbackPin,caller,c,i,static_cast<ifnet_t>(arg0));
    if (error) {ScanDiagnostics::record(ScanDiagnostics::PrivateEntry,error);return error;}
    ControllerRecord *r=getRecord(c,i,true);
    if (!r) return ENXIO;
    Context context {c,i,static_cast<ifnet_t>(arg0),r,{},thread(),0,
        ScanCompat::read32(static_cast<const uint8_t *>(arg1)+24)==AssociationCompat::NativeSize};
    if (!PrivateMAC::BSDLease::held(c,i,context.ifp,&context.generation)) return ESTALE;
    error=r->admission.enter(r->binding,thread(),context.admission);
    if (error) {ScanDiagnostics::record(ScanDiagnostics::PrivateEntry,error);return error;}
    add(context);ScanDiagnostics::record(ScanDiagnostics::PrivateEntry,0);
    error=originalPerform(i,c,command,arg0,arg1);
    remove(context);
    // State mutation is only in the original gated driver path. Admission is
    // atomic and may be released after executeCommand has returned to BSD.
    const int finished=r->admission.finish(context.admission,thread());
    return error?error:finished;
}
bool within(uintptr_t function,uintptr_t base,size_t size,size_t needed) {
    return function>=base && function-base<=size && needed<=size-(function-base);
}
}

int entryAllowed(void *c,void *i) {
    if (!enabled()) return 0;
    Context *context=findContext(c,i);
    if (!contextLive(context)) return EOPNOTSUPP;
    return 0;
}
bool available(void *c,void *i) {return enabled() && !entryAllowed(c,i) && PrivateMAC::currentCredentialIsRoot();}

void install(KernelPatcher &patcher,const Install &input) {
    if (attempted) return;attempted=true;
    if (!input.associations || !input.associationLockOwner || !input.runtimeBuild) return;
    const auto status=PrivateMAC::initializeDriverPins(reinterpret_cast<const void *>(input.brcmAddress),input.brcmSize,pins);
    ScanDiagnostics::record(ScanDiagnostics::PrivatePins,static_cast<int32_t>(status));
    if (status!=PrivateMAC::DriverPinStatus::Passed) return;
    patcher.clearError();
    const auto perform=patcher.solveSymbol(input.legacyIndex,Perform,input.legacyAddress,input.legacySize);
    const auto callback=patcher.solveSymbol(KernelPatcher::KernelID,"_ifnet_ioctl");
    if (patcher.getError()!=KernelPatcher::Error::NoError ||
        !within(perform,input.legacyAddress,input.legacySize,14) || !callback) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::PrivateKernelCaller,1);return;
    }
    const uint8_t performGuard[]={0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x10,0x4d,0x89,0xc2,0x49,0x89,0xcb};
    if (memcmp(reinterpret_cast<const void *>(perform),performGuard,sizeof(performGuard))) {
        ScanDiagnostics::record(ScanDiagnostics::PrivateKernelCaller,2);return;
    }
    const int range=ScanKernelIdentity::verifyRunningKernelCodeRange(callback,0x218);
    if (range) {ScanDiagnostics::record(ScanDiagnostics::PrivateKernelCaller,range);return;}
    const int pin=callbackPin.prepare(reinterpret_cast<const uint8_t *>(callback),0x218,true,input.runtimeBuild);
    ScanDiagnostics::record(ScanDiagnostics::PrivateKernelCaller,pin);if (pin) return;
    bridgeLock=IOLockAlloc();if (!bridgeLock) return;
    config=input;
    KernelPatcher::RouteRequest driverRoute(Associate,wrappedDriverAssociate,originalAssociate);
    if (!patcher.routeMultiple(input.brcmIndex,&driverRoute,1,input.brcmAddress,input.brcmSize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::PrivateDriverRoute,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::PrivateDriverRoute,0);
    KernelPatcher::RouteRequest authRoute(Auth,wrappedAuth,originalAuth);
    if (!patcher.routeMultiple(input.brcmIndex,&authRoute,1,input.brcmAddress,input.brcmSize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::PrivateAuthRoute,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::PrivateAuthRoute,0);
    KernelPatcher::RouteRequest bsdRoute(Perform,wrappedPerform,originalPerform);
    if (!patcher.routeMultiple(input.legacyIndex,&bsdRoute,1,input.legacyAddress,input.legacySize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::PrivateBSDRoute,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::PrivateBSDRoute,0);
    __atomic_store_n(&ready,true,__ATOMIC_RELEASE);
    ScanDiagnostics::record(ScanDiagnostics::PrivateReady,0);
}
} // namespace PrivateBridge
