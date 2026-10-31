#include "legacy_install.hpp"
#include "legacy_bridge.hpp"
#include "bsd_set_adapter.hpp"
#include "provider_contract.hpp"
#include "cache_provider_contract.hpp"
#include "cache_access.hpp"
#include "cache_kernel.hpp"
#include "disassociate_admission.hpp"
#include "disassociate_kernel.hpp"
#include "disassociate_config.hpp"
#include "event_contracts.hpp"
#include "event_router.hpp"
#include "event_binding_registry.hpp"
#include "scan_sequence_kernel.hpp"
#include "../scan_kernel/primary_interface_iokit.hpp"
#include <IOKit/IOLib.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOTimerEventSource.h>
#include <kern/thread.h>
#include <machine/machine_routines.h>
#include <libkern/c++/OSDictionary.h>
#include <sys/proc.h>

// This data symbol belongs to IONetworkingFamily, already a linked dependency,
// rather than the inner kernel symbol table. Let the kext loader resolve it
// independently; never infer it from the provider GOT slot being checked.
extern "C" const uint8_t legacyNativeEthernetVTable[] __asm("__ZTV19IOEthernetInterface");

namespace LegacyWiFi { namespace Installer { namespace {
namespace P=ProviderContract;
namespace C=CacheProviderContract;
namespace E=EventContracts;
namespace B=LegacyBridge;
namespace S=ScanSequenceKernel;
namespace D=DisassociateKernel;

static_assert(CacheAccess::ManagerHeadOffset==C::ManagerCacheHeadOffset &&
              CacheAccess::ManagerSize==C::ScanManagerInstanceSize &&
              CacheAccess::NodeSize==C::CacheNodeSize &&
              CacheAccess::PreviousLinkOffset==C::CacheNodePreviousLinkOffset &&
              CacheAccess::ReferenceCountOffset==C::CacheNodeReferenceCountOffset &&
              CacheAccess::ResultOffset==C::CacheNodeScanResultOffset,
              "cache access must use the verified provider layout");

struct Provider {
    E::LoadedImage image {};
    E::ProviderSymbols events {};
    P::Imports imports {};
    uintptr_t symbols[P::SymbolCount] {};
    C::Symbols cacheSymbols {};
    C::Imports cacheImports {};
    size_t index=0;
    bool verified=false;
    bool cacheVerified=false;
};
Provider provider;
struct Driver {
    E::LoadedImage image {};
    E::DriverSymbols symbols {};
    bool resolved=false;
    DisassociateAdmission::Admission disconnect;
    bool disconnectAttempted=false;
};
Driver drivers[2];
bool kernelVerified=false,attempted=false,sequenceAttempted=false;
uint32_t active=0,verifiedDrivers[2] {};
B::Runtime runtime;
B::Handler originalScan=nullptr,originalCapabilities=nullptr;
B::Handler originalState=nullptr,originalAPIEList=nullptr;
B::Handler originalAssociate=nullptr,originalMultiple=nullptr;
B::Handler originalSingle=nullptr;
B::Handler originalAuth=nullptr;
B::Handler originalDisassociate=nullptr;
B::CopyIn originalCopyIn=nullptr;
B::CopyOut originalCopyOut=nullptr;
struct EventLock {
    IOSimpleLock *value=nullptr;
    IOInterruptState restore=0;
};
EventLock eventLock;
E::InterfaceBindingRegistry interfaceBindings;

uintptr_t currentThread() {return reinterpret_cast<uintptr_t>(current_thread());}
bool eventContextIsUnsafe(void *) {
    return ml_at_interrupt_context() || !ml_get_interrupts_enabled();
}
void *allocate(size_t size) {return IOMallocZero(size);}
void deallocate(void *p,size_t size) {IOFree(p,size);}
void lock(void *p) {IOLockLock(static_cast<IOLock *>(p));}
void unlock(void *p) {IOLockUnlock(static_cast<IOLock *>(p));}
void eventLockEnter(void *p) {
    auto &state=*static_cast<EventLock *>(p);
    const auto restore=IOSimpleLockLockDisableInterrupt(state.value);
    state.restore=restore; // Protected by the acquired lock.
}
void eventLockLeave(void *p) {
    auto &state=*static_cast<EventLock *>(p);
    const auto restore=state.restore;
    IOSimpleLockUnlockEnableInterrupt(state.value,restore);
}
bool installed() {return __atomic_load_n(&active,__ATOMIC_ACQUIRE)!=0;}

int family(IOService *controller,IOService *interface) {
    if (!controller || !interface || controller->isInactive() || interface->isInactive() ||
        interface->getProvider()!=controller) return -1;
    for (unsigned n=0;n<2;n++) {
        const auto kind=n==0?E::DriverKind::Broadcom4331:E::DriverKind::Broadcom43224;
        if (__atomic_load_n(&verifiedDrivers[n],__ATOMIC_ACQUIRE) &&
            PrimaryInterface::exactClass(controller,E::controllerClassName(kind)) &&
            PrimaryInterface::exactClass(interface,E::interfaceClassName(kind)) &&
            interface->getMetaClass()->getClassSize()>=P::InterfaceScanManagerOffset+sizeof(void *))
            return static_cast<int>(n);
    }
    return -1;
}
bool primary(void *c,void *i,const char requestName[16]) {
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    if (family(controller,interface)<0 || !requestName) return false;
    PrimaryInterface::BSDNameProperty name;
    char request[16];memcpy(request,requestName,sizeof(request));
    return PrimaryInterface::copyBSDName(interface,name) &&
        PrimaryInterface::sameRequestAndProperty(request,name.bytes,name.length);
}
NetworkIdentity::Source disconnectSource(void *c,void *i) {
    const int selected=family(static_cast<IOService *>(c),static_cast<IOService *>(i));
    return selected==0?NetworkIdentity::Source::Pinned4331:
        selected==1?NetworkIdentity::Source::Pinned43224:NetworkIdentity::Source::Unknown;
}
int disconnectMetadata(void *c,void *i,void *v,B::Request *r,bool wide,
                        uint32_t reason,uint32_t flush) {
    return D::perform(originalDisassociate,c,i,v,r,wide,reason,flush);
}
bool enhancedReasonConfiguration(void *controller,bool *enabled) {
    auto *service=static_cast<IOService *>(controller);
    if (!service || service->isInactive()) return false;
    auto *pci=service->getProvider();
    if (!pci || pci->isInactive() || !pci->metaCast("IOPCIDevice")) return false;
    // The admitted old PCIe controller is this bridge's provisioning service.
    // Its PCI provider/ancestor properties are shared with the native PCIe
    // topology; sibling-service-only properties are not copied or inferred.
    return DisassociateConfig::read(service,enabled);
}
bool multiple(void *c,void *i) {
    return family(static_cast<IOService *>(c),static_cast<IOService *>(i))==0;
}
NetworkIdentity::Source classifyCacheInitialization(void *c,void *i) {
    // The native initializer's caller owns these live arguments. Attachment
    // need not be complete yet; allocation observation does not authorize a
    // later cache mutation or dereference of these stored raw pointers.
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    if (!controller || !interface) return NetworkIdentity::Source::Unknown;
    for (unsigned n=0;n<2;++n) {
        const auto kind=n==0?E::DriverKind::Broadcom4331:E::DriverKind::Broadcom43224;
        if (__atomic_load_n(&verifiedDrivers[n],__ATOMIC_ACQUIRE) &&
            PrimaryInterface::exactClass(controller,E::controllerClassName(kind)) &&
            PrimaryInterface::exactClass(interface,E::interfaceClassName(kind)))
            return n==0?NetworkIdentity::Source::Pinned4331:NetworkIdentity::Source::Pinned43224;
    }
    return NetworkIdentity::Source::Unknown;
}
void retainCacheObject(void *object) {
    // Bypass both retain and taggedRetain overrides. OSObject::retain itself
    // dispatches taggedRetain virtually; the qualified leaf performs only the
    // base reference increment for this already-held object.
    static_cast<OSObject *>(object)->OSObject::taggedRetain(nullptr);
}
void releaseCacheObject(void *object) {
    static_cast<OSObject *>(object)->release();
}
bool cacheObjectBinding(void *m,void *c,void *i,void *w,void *t) {
    if (!m || !c || !i || !w || !t || eventContextIsUnsafe(nullptr)) return false;
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    auto *manager=static_cast<OSObject *>(m);
    auto *loop=static_cast<IOWorkLoop *>(w);
    auto *timer=static_cast<IOTimerEventSource *>(t);
    const auto *meta=manager->getMetaClass(),*timerMeta=timer->getMetaClass();
    return meta && !strcmp(meta->getClassName(),"IO80211ScanManager") &&
        meta->getClassSize()==C::ScanManagerInstanceSize &&
        timerMeta && !strcmp(timerMeta->getClassName(),"IOTimerEventSource") &&
        interface->getMetaClass()->getClassSize()>=P::InterfaceScanManagerOffset+sizeof(void *) &&
        controller->getWorkLoop()==loop && interface->getWorkLoop()==loop &&
        timer->getWorkLoop()==loop && loop->IOWorkLoop::inGate();
}
bool validateCacheInitialization(void *m,void *c,void *i,void *w,void *t) {
    return cacheObjectBinding(m,c,i,w,t);
}
bool validateCacheBinding(void *m,void *c,void *i,void *w,void *t,
                          NetworkIdentity::Source source) {
    const int selected=family(static_cast<IOService *>(c),static_cast<IOService *>(i));
    return ((selected==0 && source==NetworkIdentity::Source::Pinned4331) ||
            (selected==1 && source==NetworkIdentity::Source::Pinned43224)) &&
        cacheObjectBinding(m,c,i,w,t);
}
IOReturn stopCacheTimer(OSObject *,void *t,void *,void *,void *) {
    auto *timer=static_cast<IOTimerEventSource *>(t);
    // The guarded provider creates the default passive timer. Under its gate,
    // disable/cancel suppress queued generations without waiting on the gate
    // they themselves hold; an already-running action has finished before us.
    timer->disable();
    timer->cancelTimeout();
    return kIOReturnSuccess;
}
void quiesceCacheTimer(void *w,void *t) {
    auto *loop=static_cast<IOWorkLoop *>(w);
    // Call the public base implementation, whose action is synchronous. Only
    // this short action holds the gate; superclass interface detach runs later.
    // The base implementation unconditionally calls the action and returns its
    // result; stopCacheTimer cannot fail or omit the disable/cancel operation.
    (void)loop->IOWorkLoop::runAction(stopCacheTimer,loop,t);
}
bool scanDoneCapability(void *c,void *i) {
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    const int selectedFamily=family(controller,interface);
    if (selectedFamily<0) return false;
    if (selectedFamily==1 && !S::ready()) return false;
    auto *loop=controller->getWorkLoop();
    if (!loop || interface->getWorkLoop()!=loop || !loop->inGate()) return false;
    const auto kind=selectedFamily==0?E::DriverKind::Broadcom4331:E::DriverKind::Broadcom43224;
    if (!interfaceBindings.bind(controller,interface,kind)) return false;
    return E::shared().mayAdvertiseCapability46(interface);
}
bool eventBinding(void *,void *i,E::DriverKind kind,char bsdName[E::InterfaceNameSize]) {
    return interfaceBindings.lookup(i,kind,bsdName);
}
uintptr_t eventThread(void *) {return currentThread();}
bool suppressEvent(void *context,void *interface,uint32_t code) {
    return S::shouldSuppress(context,interface,code);
}
void afterEvent(void *context,void *interface,uint32_t code) {
    S::afterPost(context,interface,code);
}
void *scanManager(void *i) {
    void *manager=nullptr;
    memcpy(&manager,static_cast<const uint8_t *>(i)+P::InterfaceScanManagerOffset,sizeof(manager));
    return manager;
}
bool eligibleSequence(void *,IOService *controller,IOService *interface,void *manager) {
    if (ml_at_interrupt_context() || !ml_get_interrupts_enabled() ||
        family(controller,interface)!=1 || !manager || scanManager(interface)!=manager)
        return false;
    auto *loop=controller->getWorkLoop();
    if (!loop || interface->getWorkLoop()!=loop || !loop->inGate()) return false;
    const auto *meta=static_cast<OSObject *>(manager)->getMetaClass();
    // Fixed injected dependency's MetaClass constructor declares 0xb0 bytes.
    // Never interpret another manager class using this provider's offsets.
    if (!meta || strcmp(meta->getClassName(),"IO80211ScanManager") ||
        meta->getClassSize()!=0xb0) return false;
    return interfaceBindings.bind(controller,interface,E::DriverKind::Broadcom43224) &&
        E::shared().supportsInterface(interface,E::DriverKind::Broadcom43224);
}
int submitSequence(void *,void *c,void *i,const uint8_t *bytes,size_t size) {
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    if (!S::ready() || family(controller,interface)!=1 || !eligibleSequence(nullptr,controller,interface,
                                                      scanManager(interface)))
        return EOPNOTSUPP;
    return S::submit(controller,interface,bytes,size);
}
int currentPID() {return proc_selfpid();}
bool peekSequence(void *,void *c,void *i,int pid,uint8_t *bytes,size_t size,
                  uint64_t *token,int *error) {
    return S::peekManagedResult(static_cast<IOService *>(c),static_cast<IOService *>(i),
                               pid,bytes,size,token,error);
}
bool commitSequence(void *,void *i,int pid,uint64_t token,bool copiedOut) {
    return S::commitManagedResult(static_cast<IOService *>(i),pid,token,copiedOut);
}
int prepareSequenceAssociation(void *,void *i) {
    // The independent 4331 path has no managed split-scan state.
    return S::ready()?S::prepareAssociation(static_cast<IOService *>(i)):0;
}
int checkSequenceBusy(void *,void *i) {
    return S::checkBusy(static_cast<IOService *>(i));
}
int invalidateSequenceResults(void *,void *i) {
    return S::invalidateResults(static_cast<IOService *>(i));
}
void tryInstallSequence(KernelPatcher &patcher) {
    if (sequenceAttempted || !installed() || !provider.verified ||
        !__atomic_load_n(&verifiedDrivers[1],__ATOMIC_ACQUIRE) || !E::shared().ready())
        return;
    sequenceAttempted=true;
    auto *owner=OSDictionary::withCapacity(1);
    if (!owner) return;
    S::API api;api.eligible43224=eligibleSequence;
    const bool enabled=S::initialize(patcher,provider.index,
        reinterpret_cast<mach_vm_address_t>(provider.image.mappedHeader),
        provider.image.mappedSize,owner,E::shared(),api);
    owner->release();
    SYSLOG("elcap","43224 scan sequence %s",enabled?"installed":"unavailable");
}

void tryInstallDisconnect(KernelPatcher &patcher) {
    if (!installed() || !provider.verified || !provider.cacheVerified || !CacheKernel::ready()) return;
    for (unsigned n=0;n<2;++n) {
        auto &driver=drivers[n];
        if (driver.disconnectAttempted || !driver.disconnect.ready ||
            !__atomic_load_n(&verifiedDrivers[n],__ATOMIC_ACQUIRE)) continue;
        driver.disconnectAttempted=true;
        const bool enabled=D::installChild(patcher,driver.disconnect);
        SYSLOG("elcap","%s disconnect observation %s",n==0?"4331":"43224",enabled?"installed":"unavailable");
    }
}

// An installed detour has an inactive fallback while the Runtime is unpublished.
// The lossy SET guards reject new fields even in this state. A failed route
// cannot protect a handler that was never hooked; installation is a candidate
// prerequisite, not a guarantee that the native provider is globally disabled.
using RequestMethod=int (B::Runtime::*)(void *,void *,void *,B::Request *,bool);
int dispatch(RequestMethod method,void *c,void *i,void *v,B::Request *r,bool wide) {
    if (eventContextIsUnsafe(nullptr)) return EWOULDBLOCK;
    auto *controller=static_cast<IOService *>(c),*interface=static_cast<IOService *>(i);
    if (family(controller,interface)>=0) {
        // The audited provider's BSD performCommand path invokes its Apple80211
        // handler through the controller's gated executeCommand. Keep that gate
        // held for admission, native dispatch, and result invalidation together.
        // An unknown ungated caller is refused instead of acquiring a lock in
        // an unverified order or allowing a sequence to start between steps.
        auto *loop=controller->getWorkLoop();
        if (!loop || interface->getWorkLoop()!=loop || !loop->inGate())
            return EOPNOTSUPP;
    }
    return (runtime.*method)(c,i,v,r,wide);
}
int scan(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::getScanResult,c,i,v,r,wide);
    return originalScan?originalScan(c,i,v,r,wide):ENXIO;
}
int capabilities(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::getCapabilities,c,i,v,r,wide);
    return originalCapabilities?originalCapabilities(c,i,v,r,wide):ENXIO;
}
int state(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::getStateReq,c,i,v,r,wide);
    return originalState?originalState(c,i,v,r,wide):ENXIO;
}
int getAPIEList(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::getAPIEList,c,i,v,r,wide);
    return originalAPIEList?originalAPIEList(c,i,v,r,wide):ENXIO;
}
int associate(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::setAssociateRequest,c,i,v,r,wide);
    if (r && r->type==20 && r->length>B::LegacyAssociationCopySize) return EOPNOTSUPP;
    return originalAssociate?originalAssociate(c,i,v,r,wide):ENXIO;
}
int authType(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::setAuthType,c,i,v,r,wide);
    if (r && r->type==2 && r->length>BSDSetAdapter::AuthLegacySize) return EOPNOTSUPP;
    return originalAuth?originalAuth(c,i,v,r,wide):ENXIO;
}
__attribute__((noinline)) int disassociate(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) {
        // Metadata adaptation borrows child state inside the synchronous BSD
        // ioctl lifetime. Do not grant it to an arbitrary direct handler call.
        const uintptr_t caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
        if (r && r->type==22 && r->length && (!provider.cacheVerified ||
            !C::isCanonicalSetDisassociateHandlerDispatch(
                {provider.image.mappedHeader,provider.image.mappedSize,
                 reinterpret_cast<uintptr_t>(provider.image.mappedHeader)},
                caller,provider.symbols[P::SetDisassociate]))) return EOPNOTSUPP;
        return dispatch(&B::Runtime::setDisassociate,c,i,v,r,wide);
    }
    if (r && r->type==22 && r->length) return EOPNOTSUPP;
    return originalDisassociate?originalDisassociate(c,i,v,r,wide):ENXIO;
}
int scanMultiple(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::setScanRequestMultiple,c,i,v,r,wide);
    if (r && r->type==86 && r->length>ScanMultipleBridge::ElCapSize) return EOPNOTSUPP;
    return originalMultiple?originalMultiple(c,i,v,r,wide):ENXIO;
}
int scanSingle(void *c,void *i,void *v,B::Request *r,bool wide) {
    if (installed()) return dispatch(&B::Runtime::setScanRequest,c,i,v,r,wide);
    if (r && r->type==10 && r->length!=P::SingleRequestMaxSize) return EOPNOTSUPP;
    return originalSingle?originalSingle(c,i,v,r,wide):ENXIO;
}
int copyIn(void *c,uint64_t source,void *destination,size_t size) {
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (installed()) return runtime.copyIn(c,source,destination,size,caller);
    return originalCopyIn?originalCopyIn(c,source,destination,size):ENXIO;
}
int copyOut(void *c,const void *source,uint64_t destination,size_t size) {
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (installed()) return runtime.copyOut(c,source,destination,size,caller);
    return originalCopyOut?originalCopyOut(c,source,destination,size):ENXIO;
}

uintptr_t resolve(KernelPatcher &patcher,size_t index,const char *name,
                  mach_vm_address_t address,size_t size) {
    return patcher.solveSymbol(index,name,address,size);
}

void verifyCacheProvider(KernelPatcher &patcher,mach_vm_address_t address,size_t size) {
    if (!provider.verified) return;
    bool resolved=true;
    for (size_t n=0;n<C::FunctionCount;++n) {
        patcher.clearError();
        provider.cacheSymbols.addresses[n]=resolve(patcher,provider.index,
            C::Functions[n].name,address,size);
        resolved=resolved && provider.cacheSymbols.addresses[n] &&
            patcher.getError()==KernelPatcher::Error::NoError;
    }
    for (size_t n=0;n<C::ImportCount;++n) {
        patcher.clearError();
        // Resolve independently of the provider image. The networking-family
        // vtable is an ordinary loader-resolved data import; the other symbols
        // belong to XNU and come from the running inner kernel symbol source.
        provider.cacheImports.addresses[n]=n==C::EthernetInterfaceVTable ?
            reinterpret_cast<uintptr_t>(legacyNativeEthernetVTable) :
            patcher.solveSymbol(KernelPatcher::KernelID,C::ImportNames[n]);
        resolved=resolved && provider.cacheImports.addresses[n] &&
            patcher.getError()==KernelPatcher::Error::NoError;
    }
    E::Detail::ParsedImage parsed {};
    provider.cacheVerified=resolved && E::Detail::parseImage(provider.image,parsed) &&
        C::verify({provider.image.mappedHeader,size,address},parsed.uuid,
                  provider.cacheSymbols,provider.cacheImports);
    patcher.clearError();
    SYSLOG("elcap","selective cache contract %s",
           provider.cacheVerified?"verified":"unavailable");
}
E::ProviderSymbols resolveEvents(KernelPatcher &patcher,size_t index,
                                 mach_vm_address_t a,size_t s) {
    return {
        resolve(patcher,index,"__ZN16IO80211Interface10getBSDNameEv",a,s),
        resolve(patcher,index,"__ZN16IO80211Interface11postMessageEjPvm",a,s),
        resolve(patcher,index,"__Z27IO80211InterfacePostMessagePcjPvm",a,s),
        resolve(patcher,index,"__ZN18IO80211ScanManager8scanDoneEb",a,s),
        resolve(patcher,index,"__ZN16IO80211QueueCall12kev_post_msgEP7kev_msg",a,s)
    };
}
void verifyDrivers() {
    for (unsigned n=0;n<2;n++) {
        const auto kind=n==0?E::DriverKind::Broadcom4331:E::DriverKind::Broadcom43224;
        const bool valid=provider.verified && drivers[n].resolved &&
            E::verifyDriver(drivers[n].image,kind,drivers[n].symbols,provider.image,provider.events);
        __atomic_store_n(&verifiedDrivers[n],valid?1U:0U,__ATOMIC_RELEASE);
        if (valid) E::shared().admitDriver(drivers[n].image,kind,drivers[n].symbols);
    }
}
void install(KernelPatcher &patcher) {
    if (!kernelVerified || !provider.verified || attempted) return;
    attempted=true;
    auto *registryLock=IOLockAlloc();
    if (!registryLock) {SYSLOG("elcap","request adapter refused: allocation failed");return;}
    const auto a=reinterpret_cast<mach_vm_address_t>(provider.image.mappedHeader);
    const auto s=provider.image.mappedSize;
    if (provider.cacheVerified) {
        CacheKernel::API cacheAPI;cacheAPI.classifyInitialization=classifyCacheInitialization;
        cacheAPI.validateInitialization=validateCacheInitialization;
        cacheAPI.validateBinding=validateCacheBinding;
        cacheAPI.retainObject=retainCacheObject;cacheAPI.releaseObject=releaseCacheObject;
        cacheAPI.quiesceTimer=quiesceCacheTimer;
        const bool cacheReady=CacheKernel::initialize(patcher,provider.index,a,s,
                                                      provider.cacheVerified,cacheAPI);
        SYSLOG("elcap","cache lifecycle observation %s",cacheReady?"installed":"unavailable");
    }
    D::API disconnectAPI;
    disconnectAPI.classify=disconnectSource;disconnectAPI.currentThread=currentThread;
    disconnectAPI.allocate=allocate;disconnectAPI.deallocate=deallocate;
    disconnectAPI.enhancedReasonConfiguration=enhancedReasonConfiguration;
    (void)D::initialize(disconnectAPI);
    // Install the lossy SET guards before the fallible copy/read routes. Until
    // the final release-store they reject unsupported schemas and all other
    // detours retain their original path; the Runtime is never half published.
    KernelPatcher::RouteRequest routes[]={
        {P::Names[P::SetDisassociate],disassociate,originalDisassociate},
        {P::Names[P::SetAuth],authType,originalAuth},
        {P::Names[P::Associate],associate,originalAssociate},
        {P::Names[P::Multiple],scanMultiple,originalMultiple},
        {P::Names[P::SetSingle],scanSingle,originalSingle},
        {P::Names[P::CopyIn],copyIn,originalCopyIn},
        {P::Names[P::CopyOut],copyOut,originalCopyOut},
        {P::Names[P::Scan],scan,originalScan},
        {P::Names[P::Capabilities],capabilities,originalCapabilities},
        {P::Names[P::State],state,originalState},
        {P::Names[P::APIEList],getAPIEList,originalAPIEList}
    };
    for (auto &route:routes) {
        if (!patcher.routeMultiple(provider.index,&route,1,a,s)) {
            patcher.clearError();IOLockFree(registryLock);
            SYSLOG("elcap","request routing incomplete; converted requests remain disabled");return;
        }
    }
    eventLock.value=IOSimpleLockAlloc();
    if (eventLock.value && interfaceBindings.initialize()) {
        E::RouterAPI events;
        events.lookupBoundInterface=eventBinding;events.eventContextIsUnsafe=eventContextIsUnsafe;
        events.currentThread=eventThread;
        events.shouldSuppress=suppressEvent;events.afterPost=afterEvent;
        events.eventContextViolation=S::eventContextViolation;
        events.scopeLock={&eventLock,eventLockEnter,eventLockLeave};
        if (!E::install(patcher,provider.index,provider.image,provider.events,events))
            SYSLOG("elcap","event route incomplete; scan-wait capability remains disabled");
        // configure() retains the lock callbacks even after a partial route.
        // This bounded resident lock must therefore outlive all detours.
        verifyDrivers();
    }
    B::API api;
    api.getScanResult=originalScan;api.getCapabilities=originalCapabilities;
    api.getStateReq=originalState;api.getAPIEList=originalAPIEList;
    api.setAssociateRequest=originalAssociate;api.setScanRequestMultiple=originalMultiple;
    api.setScanRequest=originalSingle;
    api.setAuthType=originalAuth;
    api.setDisassociate=originalDisassociate;
    api.setDisassociateMetadata=disconnectMetadata;
    api.copyIn=originalCopyIn;api.copyOut=originalCopyOut;
    api.allocate=allocate;api.deallocate=deallocate;api.currentThread=currentThread;
    api.scanManager=scanManager;
    api.getResult=reinterpret_cast<ScanBridge::GetResult>(provider.symbols[P::GetResult]);
    api.primaryInterface=primary;api.supportsMultiple=multiple;
    api.admitScanEventCapabilities=scanDoneCapability;
    api.currentPID=currentPID;api.submitSingleSequence=submitSequence;
    api.peekManagedGet11=peekSequence;api.commitManagedGet11=commitSequence;
    api.prepareAssociation=prepareSequenceAssociation;
    api.checkManagedScanBusy=checkSequenceBusy;
    api.invalidateManagedResults=invalidateSequenceResults;
    api.associationCopyInCaller=a+P::AssociationCopyReturn;
    api.multipleCopyInCaller=a+P::MultipleCopyReturn;
    api.singleCopyInCaller=a+P::SingleCopyReturn;
    api.getAPIEListCopyOutCaller=a+P::GetAPIEListCopyOutReturn;
    api.authCopyInCaller=a+P::AuthCopyInReturn;
    api.registryLock={registryLock,lock,unlock};
    if (!runtime.prepare(api)) {
        IOLockFree(registryLock);SYSLOG("elcap","request adapter refused: incomplete API");return;
    }
    __atomic_store_n(&active,1U,__ATOMIC_RELEASE);
    SYSLOG("elcap","bounded legacy request adapter installed");
}
} // namespace

void observe(KernelPatcher &patcher,ImageKind kind,size_t index,
             mach_vm_address_t address,size_t size) {
    patcher.clearError();
    E::LoadedImage image{reinterpret_cast<const uint8_t *>(address),size};
    if (kind==ImageKind::Provider) {
        if (provider.image.mappedHeader) return; // No replacement/retry after routing.
        provider.image=image;provider.index=index;
        provider.events=resolveEvents(patcher,index,address,size);
        provider.imports={
            patcher.solveSymbol(KernelPatcher::KernelID,"_IOMalloc"),
            patcher.solveSymbol(KernelPatcher::KernelID,"_IOFree")
        };
        for (size_t n=0;n<P::SymbolCount;n++)
            provider.symbols[n]=resolve(patcher,index,P::Names[n],address,size);
        provider.verified=patcher.getError()==KernelPatcher::Error::NoError &&
            E::verifyProvider(image,provider.events) &&
            P::verify({image.mappedHeader,size,address},provider.symbols,provider.imports);
        if (!provider.verified) SYSLOG("elcap","provider image contract rejected");
        // All cache fingerprints are checked before install() can route any
        // provider entry point. This only prepares the cache contract; it does
        // not enable nonzero SET22 actions without their child/command bridge.
        verifyCacheProvider(patcher,address,size);
    } else {
        const bool is4331=kind==ImageKind::Broadcom4331;
        auto &driver=drivers[is4331?0:1];
        if (driver.image.mappedHeader) return;
        driver.image=image;
        driver.symbols={
            resolve(patcher,index,is4331?
                "__ZN16AirPort_Brcm433120apple80211_scan_doneEPviP10wlc_bsscfg":
                "__ZN17AirPort_Brcm4322420apple80211_scan_doneEPvi",address,size),
            resolve(patcher,index,is4331?
                "__ZN16AirPort_Brcm433112scanCompleteEP12wlc_bss_list":
                "__ZN17AirPort_Brcm4322412scanCompleteEP14wlc_bss_list_t",address,size)
        };
        // A driver may be observed before its provider during an already-
        // loaded traversal. Stored images are revisited by the owner below.
        // The complete driver contract is checked only with its real provider.
        driver.resolved=patcher.getError()==KernelPatcher::Error::NoError;
        // Verify before any disconnect entry is routed; retain this immutable
        // pre-route admission when the worker/disable/setter entries change.
        const auto child=is4331?DisassociateChildContract::Brcm4331:
                                DisassociateChildContract::Brcm43224;
        (void)DisassociateAdmission::verifyChild(patcher,index,address,size,child,&driver.disconnect);
    }
    patcher.clearError();verifyDrivers();install(patcher);tryInstallSequence(patcher);tryInstallDisconnect(patcher);
}
void kernelReady(KernelPatcher &patcher) {
    kernelVerified=true;install(patcher);tryInstallSequence(patcher);tryInstallDisconnect(patcher);
}
} } // namespace LegacyWiFi::Installer
