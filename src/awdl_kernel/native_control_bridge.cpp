#include "native_control_bridge.hpp"
#include "version_external_method.hpp"
#include "control_query_shape.hpp"
#include "scoped_reset.hpp"
#ifdef AIRPORT_BRCM_EVENT_PIPE
#include "event_pipe_router.hpp"
#include "event_dispatch_shape.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#endif
#include <IOKit/IOLib.h>
#include <IOKit/IOMemoryDescriptor.h>
#include <IOKit/network/IONetworkController.h>
#include <kern/task.h>
#include <machine/machine_routines.h>
#include <string.h>

namespace AWDLKernel { namespace NativeControlBridge { namespace {
using NewClient=IOReturn (*)(IOService *,task_t,void *,uint32_t,OSDictionary *,IOUserClient **);
using External=IOReturn (*)(IOUserClient *,uint32_t,IOExternalMethodArguments *,
                            IOExternalMethodDispatch *,OSObject *,void *);
using Alloc=OSObject *(*)(const OSMetaClass *);
using Init=bool (*)(IOUserClient *,task_t,uint32_t);
using Start=bool (*)(IOUserClient *,IOService *);
using Terminate=bool (*)(IOService *,IOOptionBits);
using WillTerminate=bool (*)(IOService *,IOService *,IOOptionBits);
using StopLocal=void (*)(IOService *);
using GetRole=uint32_t (*)(IOService *);
using GetBSDName=const char *(*)(IOService *);
constexpr const char *NewName="__ZN23IO80211VirtualInterface13newUserClientEP4taskPvjP12OSDictionaryPP12IOUserClient";
constexpr const char *ExternalName="__ZN27IO80211AsyncEventUserClient14externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv";
constexpr const char *AllocName="__ZNK27IO80211AsyncEventUserClient9MetaClass5allocEv";
constexpr const char *MetaName="__ZN27IO80211AsyncEventUserClient10gMetaClassE";
constexpr const char *InitName="__ZN27IO80211AsyncEventUserClient12initWithTaskEP4task21kIO80211InterfaceType";
constexpr const char *StartName="__ZN27IO80211AsyncEventUserClient5startEP9IOService";
constexpr const char *VirtualTerminateName="__ZN23IO80211VirtualInterface9terminateEj";
constexpr const char *WillTerminateName="__ZN23IO80211VirtualInterface13willTerminateEP9IOServicej";
constexpr const char *BrcmTerminateName="__ZN15AirPort_BrcmNIC9terminateEj";
constexpr const char *StopName="__ZN15AirPort_BrcmNIC10stop_localEv";
// Complete instruction prefixes only, before external relocation-bearing
// instructions. Full mapped UUID/text/role/GET43 pins are checked separately.
constexpr uint8_t NewGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50,0x4d,0x89,0xce,0x41,0x89,0xcf,0x49,0x89,0xfc,0x49,0xc7,0x01,0,0,0,0};
constexpr uint8_t ExternalGuard[]={0x55,0x48,0x89,0xe5,0x83,0xfe,0x01,0x77,0x23};
constexpr uint8_t AllocGuard[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x8d,0x3d,0xac,0x95,0x0b,0,0xbe,0x58,0x01,0,0};
constexpr uint8_t InitGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0x48,0x81,0xec,0x10,0x01,0,0,0x89,0xd3,0x49,0x89,0xff};
constexpr uint8_t StartGuard[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x49,0x89,0xf6,0x48,0x89,0xfb};
constexpr uint8_t VirtualTerminateGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x53,0x50,0x41,0x89,0xf6,0x48,0x89,0xfb};
constexpr uint8_t WillTerminateGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x53,0x50,0x41,0x89,0xd6,0x49,0x89,0xf7,0x48,0x89,0xfb};
constexpr uint8_t BrcmTerminateGuard[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x41,0x89,0xf6,0x48,0x89,0xfb,0x48,0x8b,0x07};
constexpr uint8_t StopGuard[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x89,0xfb,0x48,0x83,0xbf,0x10,0x0a,0,0,0,0x74,0x0a};
ClientRegistry *registry=nullptr;
int (*runtimeBuildGate)()=nullptr;
DriverVersionBackend backend;
const OSMetaClass *meta=nullptr;
Alloc allocate=nullptr;Init initialize=nullptr;Start start=nullptr;
GetRole getRole=nullptr;GetBSDName getBSDName=nullptr;
NewClient originalNew=nullptr;External originalExternal=nullptr;
Terminate originalVirtualTerminate=nullptr,originalBrcmTerminate=nullptr;
WillTerminate originalWillTerminate=nullptr;StopLocal originalStop=nullptr;
volatile uint32_t state=static_cast<uint32_t>(Status::NotInstalled);
volatile bool retiring=false;
bool attempted=false;
Snapshot counters {};
#ifdef AIRPORT_BRCM_EVENT_PIPE
EventPipeRouter eventPipes;
using ClientMemory=IOReturn (*)(IOUserClient *,uint32_t,IOOptionBits *,IOMemoryDescriptor **);
ClientMemory originalMemory=nullptr;
volatile bool eventRoutesInstalled=false;
EventSnapshot eventCounters {};
constexpr const char *MemoryName="__ZN12IOUserClient19clientMemoryForTypeEjPjPP18IOMemoryDescriptor";
constexpr uint8_t MemoryGuard[]={0x55,0x48,0x89,0xe5,0xb8,0xc7,0x02,0,0xe0,0x5d,0xc3,0x0f,0x1f,0x44,0,0};
#endif
void increment(uint32_t &value) {__atomic_add_fetch(&value,1U,__ATOMIC_RELAXED);}
IOReturn openResult(IOReturn result) {
    __atomic_store_n(&counters.lastOpenResult,static_cast<uint32_t>(result),__ATOMIC_RELAXED);
    if (result==kIOReturnSuccess) increment(counters.openSucceeded);else increment(counters.openFailed);
    return result;
}
bool exactClass(IOService *object,const char *name) {
    return object && object->getMetaClass() && !strcmp(object->getMetaClass()->getClassName(),name);
}
bool sleepable() {return !ml_at_interrupt_context() && ml_get_interrupts_enabled();}
bool active() {
    return __atomic_load_n(&state,__ATOMIC_ACQUIRE)==static_cast<uint32_t>(Status::Ready) &&
           runtimeBuildGate && runtimeBuildGate()==0 &&
           !__atomic_load_n(&retiring,__ATOMIC_ACQUIRE) && ScopedResetBridge::ready();
}
#ifdef AIRPORT_BRCM_EVENT_PIPE
bool eventActive() {
#ifdef AIRPORT_BRCM_EVENT_PIPE_CANDIDATE
    return active() && __atomic_load_n(&eventRoutesInstalled,__ATOMIC_ACQUIRE) && eventPipes.ready();
#else
    return false; // The route review build never advertises an event transport.
#endif
}
IOReturn eventResult(IOReturn result) {
    __atomic_store_n(&eventCounters.lastResult,static_cast<uint32_t>(result),__ATOMIC_RELAXED);
    return result;
}
IOReturn wrappedMemory(IOUserClient *client,uint32_t type,IOOptionBits *options,
                       IOMemoryDescriptor **memory) {
    ClientWorkLease lease;
    const auto owned=registry?registry->acquire(client,lease):ClientStatus::Missing;
    if (owned==ClientStatus::Missing || owned==ClientStatus::NotPrepared)
        return originalMemory(client,type,options,memory);
    if (options) *options=0;
    if (memory) *memory=nullptr;
    if (owned!=ClientStatus::Passed || !eventActive()) return kIOReturnNotReady;
    if (!sleepable() || lease.owner()!=current_task()) return kIOReturnNotPrivileged;
    increment(eventCounters.mapAttempts);
    __atomic_store_n(&eventCounters.lastMapType,type,__ATOMIC_RELAXED);
    const auto result=eventPipes.retainMemoryForType(client,type,options,memory);
    if (result==kIOReturnSuccess) increment(eventCounters.mapSucceeded);
    return eventResult(result);
}
#endif
bool awdlProvider(IOService *provider) {
    if (!getRole || !getBSDName || !exactClass(provider,"AirPort_BrcmNIC_P2PInterface") ||
        provider->getMetaClass()->getClassSize()<0xde || getRole(provider)!=6) return false;
    const char *name=getBSDName(provider);
    return name && !memcmp(name,"awdl0",6);
}
void markProvider(IOService *provider) {
    if (!awdlProvider(provider)) return;
    __atomic_store_n(&retiring,true,__ATOMIC_RELEASE);
#ifdef AIRPORT_BRCM_EVENT_PIPE
    eventPipes.markProviderClosing(provider);
#endif
    if (registry) {ClientHandle handle;registry->beginCloseProvider(provider,handle);}
}
void markController(IOService *controller) {
    if (!exactClass(controller,"AirPort_BrcmNIC")) return;
    __atomic_store_n(&retiring,true,__ATOMIC_RELEASE);
#ifdef AIRPORT_BRCM_EVENT_PIPE
    eventPipes.markControllerClosing(controller);
#endif
    if (registry) registry->beginCloseController(controller);
}
bool wrappedVirtualTerminate(IOService *provider,IOOptionBits options) {
    if (awdlProvider(provider)) increment(counters.virtualTerminate);
    markProvider(provider);return originalVirtualTerminate(provider,options);
}
bool wrappedWillTerminate(IOService *provider,IOService *parent,IOOptionBits options) {
    if (awdlProvider(provider)) increment(counters.virtualWillTerminate);
    markProvider(provider);return originalWillTerminate(provider,parent,options);
}
bool wrappedBrcmTerminate(IOService *controller,IOOptionBits options) {
    if (exactClass(controller,"AirPort_BrcmNIC")) increment(counters.controllerTerminate);
    markController(controller);return originalBrcmTerminate(controller,options);
}
void wrappedStop(IOService *controller) {
    if (exactClass(controller,"AirPort_BrcmNIC")) increment(counters.controllerStop);
    markController(controller);originalStop(controller);
}
struct Prepared {
    uint8_t *storage=nullptr;
    VersionCall call {};
    bool prepare() {
        storage=static_cast<uint8_t *>(IOMallocZero(NativeFrameSize+NativeVersionCapacity));
        if (!storage) return false;
        const uint8_t command[]={0xc9,0x69,0x28,0xc0};
        memcpy(storage,command,sizeof(command));memcpy(storage+0x3c08,"awdl0",6);storage[0x3c18]=43;
        call.input=storage;call.inputSize=NativeFrameSize;
        call.output=storage+NativeFrameSize;call.outputCapacity=NativeVersionCapacity;return true;
    }
    ~Prepared() {if (storage) IOFree(storage,NativeFrameSize+NativeVersionCapacity);}
};
struct OpenContext {
    task_t task=TASK_NULL;
    IOService *controller=nullptr,*provider=nullptr;
    IOCommandGate *gate=nullptr;IOWorkLoop *loop=nullptr;
    Prepared *verification=nullptr;IOUserClient *result=nullptr;
    IOReturn error=kIOReturnNotReady;
};
bool live(const OpenContext &c) {
    return active() && c.task==current_task() && !c.controller->isInactive() &&
        !c.provider->isInactive() && c.provider->getProvider()==c.controller &&
        c.gate->getWorkLoop()==c.loop && c.loop->inGate() && c.gate->isEnabled() &&
        c.provider->getWorkLoop()==c.loop && c.controller->getWorkLoop()==c.loop;
}
IOReturn openAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<OpenContext *>(argument);
    if (!live(c)) return c.error;
    const auto verification=backend.get43(c.task,c.controller,c.provider,c.verification->call);
    __atomic_store_n(&counters.lastVersionStatus,static_cast<uint32_t>(verification.status),__ATOMIC_RELAXED);
    __atomic_store_n(&counters.lastBackendStatus,static_cast<uint32_t>(verification.rawBackendStatus),__ATOMIC_RELAXED);
    if (verification.status!=VersionStatus::Passed) return c.error=kIOReturnNotPrivileged;
    increment(counters.openAuthorized);
    if (registry->admission(c.provider)!=ClientStatus::Passed) return c.error=kIOReturnNoResources;
    OSObject *object=allocate(meta);
    if (!object) return c.error=kIOReturnNoMemory;
    auto *client=OSDynamicCast(IOUserClient,object);
    if (!client || object->getMetaClass()!=meta) {object->release();return c.error=kIOReturnError;}
    if (!initialize(client,c.task,2)) {client->release();return c.error=kIOReturnNotPrivileged;}
    ClientHandle handle;
    const auto reserved=registry->reserveClient(client,c.task,c.controller,c.provider,backend,
                                                c.verification->call,handle);
    if (reserved.status!=ClientStatus::Passed) {client->release();return c.error=kIOReturnNoResources;}
    if (!live(c)) {
        registry->beginClose(client,handle);ScopedResetBridge::resetFailedStart(client);
        client->release();return c.error=kIOReturnNotReady;
    }
    // The actual original method binds its private Virtual pointer and attaches.
    // No startAsyncEventUserClientForTask helper/provider+a0 assignment is used.
    if (!start(client,c.provider)) {
        registry->beginClose(client,handle);ScopedResetBridge::resetFailedStart(client);client->release();
        return c.error=kIOReturnError;
    }
    if (!live(c) || registry->activateClient(handle)!=ClientStatus::Passed) {
        registry->beginClose(client,handle);
        ScopedResetBridge::resetFailedStart(client);
        client->stop(c.provider);client->release();
        // Registry retains a bounded Closing tombstone. Never remove it while
        // the real object can still be dispatched to the old selector table.
        return c.error=kIOReturnNotReady;
    }
    c.result=client;return c.error=kIOReturnSuccess;
}
IOReturn openSerialAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<OpenContext *>(argument);
    // Captured WL serializes the enable/binding check with provider shutdown.
    // Calling gate.runAction directly from outside WL could otherwise sleep
    // forever if disable raced the earlier non-atomic isEnabled observation.
    if (!live(c)) return c.error;
    return c.gate->runAction(openAction,&c);
}
IOReturn wrappedNew(IOService *provider,task_t task,void *security,uint32_t type,
                    OSDictionary *properties,IOUserClient **out) {
    if (!active() || type || !out || !awdlProvider(provider))
        return originalNew(provider,task,security,type,properties,out);
    increment(counters.openAttempts);
    *out=nullptr;
    if (!sleepable() || task==TASK_NULL || task!=current_task()) return openResult(kIOReturnNotPrivileged);
    IOService *controller=provider->getProvider();
    if (!exactClass(controller,"AirPort_BrcmNIC")) return openResult(kIOReturnUnsupported);
    controller->retain();provider->retain();task_reference(task);
    auto *network=OSDynamicCast(IONetworkController,controller);
    IOCommandGate *gate=network?network->getCommandGate():nullptr;
    IOWorkLoop *loop=gate?gate->getWorkLoop():nullptr;
    IOReturn error=kIOReturnNotReady;
    if (gate && loop) {
        gate->retain();loop->retain();
        // Preparing a16KiB frame is outside the old gate. A caller already in
        // that gate is refused rather than allocating while holding it.
        if (!loop->inGate() && gate->isEnabled()) {
            Prepared prepared;
            if (prepared.prepare()) {
                OpenContext context {task,controller,provider,gate,loop,&prepared,nullptr,kIOReturnNotReady};
                error=loop->runAction(openSerialAction,controller,&context);
                if (error==kIOReturnSuccess) {*out=context.result;error=context.error;}
            } else error=kIOReturnNoMemory;
        }
        gate->release();loop->release();
    }
    task_deallocate(task);provider->release();controller->release();return openResult(error);
}
VersionMethodShape methodShape(const IOExternalMethodArguments &a) {
    VersionMethodShape s;
    s.version=a.version;s.selector=a.selector;s.scalarInputCount=a.scalarInputCount;
    s.scalarOutputCount=a.scalarOutputCount;s.asyncReferenceCount=a.asyncReferenceCount;
    s.wakePortPresent=a.asyncWakePort!=MACH_PORT_NULL;s.asyncReference=a.asyncReference;
    s.input=a.structureInput;s.inputSize=a.structureInputSize;s.output=a.structureOutput;
    s.outputCapacity=a.structureOutputSize;s.inputDescriptor=a.structureInputDescriptor;
    s.outputDescriptor=a.structureOutputDescriptor;s.outputDescriptorSize=a.structureOutputDescriptorSize;
    s.variableOutput=a.structureVariableOutputData;return s;
}
bool falseShape(uint32_t selector,const IOExternalMethodArguments &a) {
    return validFalseQuery(selector,methodShape(a));
}
struct MethodContext {ClientWorkLease *lease;IOExternalMethodArguments *arguments;uint32_t selector;IOReturn error;};
IOReturn methodAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<MethodContext *>(argument);auto &lease=*c.lease;
    ClientWorkLease check;
    if (!active() || registry->acquire(lease.client(),check)!=ClientStatus::Passed ||
        check.generation()!=lease.generation() || !lease.workLoop()->inGate() ||
        lease.gate()->getWorkLoop()!=lease.workLoop() || !lease.gate()->isEnabled() ||
        lease.owner()!=current_task() || lease.client()->isInactive() ||
        lease.provider()->isInactive() || lease.controller()->isInactive() ||
        lease.client()->getProvider()!=lease.provider() || lease.provider()->getProvider()!=lease.controller() ||
        lease.provider()->getWorkLoop()!=lease.workLoop() || lease.controller()->getWorkLoop()!=lease.workLoop() ||
        !awdlProvider(lease.provider())) return c.error=kIOReturnNotReady;
    if (c.selector==0) {
        increment(counters.get43Attempts);
        const auto r=runVersionExternalMethod(backend,lease.owner(),lease.controller(),lease.provider(),*c.arguments);
        __atomic_store_n(&counters.lastVersionStatus,static_cast<uint32_t>(r.status),__ATOMIC_RELAXED);
        __atomic_store_n(&counters.lastBackendStatus,static_cast<uint32_t>(r.rawBackendStatus),__ATOMIC_RELAXED);
        if (r.status==VersionStatus::Passed) increment(counters.get43Succeeded);
        return c.error=r.status==VersionStatus::Passed?kIOReturnSuccess:kIOReturnUnsupported;
    }
#ifdef AIRPORT_BRCM_EVENT_PIPE
    if (c.selector==2) {
        if (!eventActive()) return c.error=kIOReturnNotReady;
        // Adoption is the last fallible operation. Success must flow unchanged
        // through both runAction wrappers and the final MIG return below.
        increment(eventCounters.subscribeAttempts);
        c.error=eventPipes.subscribeFromSuccessfulDispatch(lease.client(),*c.arguments);
        if (c.error==kIOReturnSuccess) increment(eventCounters.subscribeSucceeded);
        return eventResult(c.error); // Atomic diagnostics cannot change Success.
    }
#endif
    if (!falseShape(c.selector,*c.arguments)) {
        increment(counters.queryShapeRejected);return c.error=kIOReturnUnsupported;
    }
    if (c.selector==1) increment(counters.query1);
    if (c.selector==5) increment(counters.query5);
    if (c.selector==7) increment(counters.query7);
    uint8_t available=0;
#ifdef AIRPORT_BRCM_EVENT_PIPE
    if (c.selector==5 && eventActive()) available=1;
#endif
    *static_cast<uint8_t *>(c.arguments->structureOutput)=available;
    c.arguments->structureOutputSize=1;return c.error=kIOReturnSuccess;
}
IOReturn methodSerialAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<MethodContext *>(argument);auto &lease=*c.lease;
    if (!active() || !lease.workLoop()->inGate() || lease.gate()->getWorkLoop()!=lease.workLoop() ||
        !lease.gate()->isEnabled()) return c.error=kIOReturnNotReady;
    return lease.gate()->runAction(methodAction,&c);
}
// OOL_COPY_BEGIN: this exact shape/copy code is also compiled by the host
// descriptor-copy fixture. That fixture tests no IOKit/task authorization.
bool validOOLVersionShape(const IOExternalMethodArguments &a) {
    // structureInput is deliberately ignored for an OOL MIG request. It is
    // never a kernel buffer authority and is never read or dereferenced here.
    return a.version==2 && !a.selector && !a.scalarInputCount && !a.scalarOutputCount &&
        a.asyncWakePort==MACH_PORT_NULL && !a.asyncReference && !a.asyncReferenceCount &&
        !a.structureInputSize && a.structureInputDescriptor &&
        a.structureOutput && a.structureOutputSize==NativeVersionCapacity &&
        !a.structureOutputDescriptor && !a.structureOutputDescriptorSize &&
        !a.structureVariableOutputData;
}
struct OwnedOOLVersionInput {
    uint8_t *bytes=nullptr;
    OwnedOOLVersionInput()=default;
    OwnedOOLVersionInput(const OwnedOOLVersionInput &)=delete;
    OwnedOOLVersionInput &operator=(const OwnedOOLVersionInput &)=delete;
    ~OwnedOOLVersionInput() {if (bytes) IOFree(bytes,NativeFrameSize);}
    IOReturn copy(IOMemoryDescriptor &descriptor) {
        // Actual MIG input is DirectionOut|CopyOnWrite and server-owned but
        // NOT prepared. Ownership of the object does not wire its user pages.
        if (bytes || descriptor.getLength()!=NativeFrameSize ||
            descriptor.getDirection()!=kIODirectionOut) return kIOReturnBadArgument;
        bytes=static_cast<uint8_t *>(IOMallocZero(NativeFrameSize));
        if (!bytes) return kIOReturnNoMemory;
        const auto prepared=descriptor.prepare(kIODirectionOut);
        if (prepared!=kIOReturnSuccess) return prepared;
        const auto copied=descriptor.readBytes(0,bytes,NativeFrameSize);
        // Every successful prepare has exactly one matching complete, even
        // for a short read. No gate/driver call occurs before complete succeeds.
        const auto completed=descriptor.complete(kIODirectionOut);
        if (completed!=kIOReturnSuccess) return completed;
        return copied==NativeFrameSize?kIOReturnSuccess:kIOReturnUnderrun;
    }
};
// OOL_COPY_END
IOReturn wrappedExternal(IOUserClient *client,uint32_t selector,IOExternalMethodArguments *args,
                         IOExternalMethodDispatch *dispatch,OSObject *target,void *reference) {
    ClientWorkLease lease;
    const auto acquired=registry?registry->acquire(client,lease):ClientStatus::Missing;
    if (acquired==ClientStatus::Missing || acquired==ClientStatus::NotPrepared)
        return originalExternal(client,selector,args,dispatch,target,reference);
    if (acquired!=ClientStatus::Passed) return kIOReturnNotReady;
    increment(counters.externalAttempts);
    __atomic_store_n(&counters.lastSelector,selector,__ATOMIC_RELAXED);
    const bool ool=selector==0 && args && args->structureInputDescriptor;
    IOExternalMethodArguments local {};
    if (ool) {local=*args;args->structureOutputSize=0;}
    bool supported=selector==0 || selector==1 || selector==5 || selector==7;
#ifdef AIRPORT_BRCM_EVENT_PIPE
    supported=supported || selector==2 || selector==3 || selector==4;
#endif
    if (!active() || !sleepable() || !args || args->selector!=selector || dispatch || target || reference ||
        !supported) return kIOReturnUnsupported;
    if (lease.owner()!=current_task()) return kIOReturnNotPrivileged;
    // No map/async original dispatch is reachable for an owned record.
    bool allowAsync=false;
#ifdef AIRPORT_BRCM_EVENT_PIPE
    allowAsync=selector==2 && eventActive();
#endif
    if (!allowAsync && (args->asyncWakePort!=MACH_PORT_NULL || args->asyncReference || args->asyncReferenceCount))
        return kIOReturnUnsupported;
    if (lease.gate()->getWorkLoop()!=lease.workLoop() || !lease.gate()->isEnabled()) return kIOReturnNotReady;
#ifdef AIRPORT_BRCM_EVENT_PIPE
    if (selector==3 || selector==4) {
        if (!eventActive() || lease.workLoop()->inGate() ||
            !validEventPipeControlShape(selector,methodShape(*args))) return kIOReturnUnsupported;
        // Allocation and final resource releases remain on the original RPC
        // thread outside the captured WL. Session runs its own short checks.
        if (selector==4) {
            increment(eventCounters.destroyAttempts);
            const auto result=eventPipes.destroy(client);
            if (result==kIOReturnSuccess) increment(eventCounters.destroySucceeded);
            return eventResult(result);
        }
        increment(eventCounters.createAttempts);
        Prepared verification;
        if (!verification.prepare()) return eventResult(kIOReturnNoMemory);
        const auto result=eventPipes.create(client,verification.call);
        if (result==kIOReturnSuccess) increment(eventCounters.createSucceeded);
        return eventResult(result);
    }
#endif
    OwnedOOLVersionInput owned;
    IOExternalMethodArguments *effective=args;
    if (ool) {
        if (lease.workLoop()->inGate() || !validOOLVersionShape(local)) return kIOReturnUnsupported;
        const auto copied=owned.copy(*local.structureInputDescriptor);
        if (copied!=kIOReturnSuccess) return copied;
        // The descriptor remains a server-owned reference. Only our matched
        // prepare/read/complete pair is added; do not release/map it or forward
        // its/user footer pointers. Its pages are completed before gate entry.
        local.structureInput=owned.bytes;local.structureInputSize=NativeFrameSize;
        local.structureInputDescriptor=nullptr;effective=&local;
    } else if (args->structureInputDescriptor) return kIOReturnUnsupported;
    MethodContext context {&lease,effective,selector,kIOReturnNotReady};
    const auto result=lease.workLoop()->runAction(methodSerialAction,lease.controller(),&context);
    const auto returned=result==kIOReturnSuccess?context.error:result;
    if (ool && returned==kIOReturnSuccess) args->structureOutputSize=local.structureOutputSize;
    return returned; // owned bytes free here, outside the captured WorkLoop gate.
}
bool span(mach_vm_address_t base,size_t extent,size_t offset,size_t length) {
    return base && base<=UINTPTR_MAX-extent && offset<=extent && length<=extent-offset;
}
template <size_t N> bool pin(KernelPatcher &patcher,size_t index,const char *symbol,
                            mach_vm_address_t base,size_t extent,size_t offset,const uint8_t (&bytes)[N]) {
    return span(base,extent,offset,N) && !memcmp(reinterpret_cast<const void *>(base+offset),bytes,N) &&
        patcher.solveSymbol(index,symbol,base,extent)==base+offset;
}
} // namespace
Status status() {
    return __atomic_load_n(&retiring,__ATOMIC_ACQUIRE)?Status::Retiring:
        static_cast<Status>(__atomic_load_n(&state,__ATOMIC_ACQUIRE));
}
bool ready() {return active();}
Snapshot snapshot() {
    Snapshot result;result.state=static_cast<uint32_t>(status());
#define COPY(member) result.member=__atomic_load_n(&counters.member,__ATOMIC_RELAXED)
    COPY(openAttempts);COPY(openAuthorized);COPY(openSucceeded);COPY(openFailed);
    COPY(get43Attempts);COPY(get43Succeeded);COPY(query1);COPY(query5);COPY(query7);
    COPY(virtualTerminate);COPY(virtualWillTerminate);COPY(controllerTerminate);COPY(controllerStop);
    COPY(lastOpenResult);COPY(lastVersionStatus);COPY(lastBackendStatus);
    COPY(externalAttempts);COPY(lastSelector);COPY(queryShapeRejected);
#undef COPY
    return result;
}
void markClientClosing(IOUserClient *client) {
#ifdef AIRPORT_BRCM_EVENT_PIPE
    ClientWorkLease owned;
    if (registry && registry->acquireClosing(client,owned)==ClientStatus::Passed)
        eventPipes.markClientClosing(client);
#else
    (void)client;
#endif
}
EventSnapshot eventSnapshot() {
    EventSnapshot result;
#ifdef AIRPORT_BRCM_EVENT_PIPE
    result.routesInstalled=__atomic_load_n(&eventRoutesInstalled,__ATOMIC_ACQUIRE);
    result.capability=eventActive()?1U:0U;
#define EVENT_COPY(member) result.member=__atomic_load_n(&eventCounters.member,__ATOMIC_RELAXED)
    EVENT_COPY(createAttempts);EVENT_COPY(createSucceeded);EVENT_COPY(destroyAttempts);EVENT_COPY(destroySucceeded);
    EVENT_COPY(mapAttempts);EVENT_COPY(mapSucceeded);EVENT_COPY(subscribeAttempts);EVENT_COPY(subscribeSucceeded);
    EVENT_COPY(lastResult);EVENT_COPY(lastMapType);
    EVENT_COPY(installStage);EVENT_COPY(installContext);EVENT_COPY(routerPrepareResult);
    EVENT_COPY(observerPrepareStatus);EVENT_COPY(observerInstallStatus);EVENT_COPY(memorySymbolPresent);
    EVENT_COPY(memoryRangeResult);EVENT_COPY(memoryGuardMatched);EVENT_COPY(memoryRouteResult);EVENT_COPY(installPatcherError);
#undef EVENT_COPY
    const auto pool=eventPipes.snapshot();
    result.retiring=pool.retiring;result.used=pool.used;result.creating=pool.creating;
    result.live=pool.live;result.closing=pool.closing;result.terminal=pool.terminal;
    result.callbacks=static_cast<uint32_t>(pool.workerCallbacks);result.committed=static_cast<uint32_t>(pool.workerCommitted);
    result.dropped=static_cast<uint32_t>(pool.workerDropped);result.full=static_cast<uint32_t>(pool.workerFull);
    result.faults=static_cast<uint32_t>(pool.workerFaults);result.queued=pool.workerQueued;
    result.running=pool.workerRunning;
#define EVENT_CODEC_COPY(member) result.member=static_cast<uint32_t>(pool.member)
    EVENT_CODEC_COPY(received46);EVENT_CODEC_COPY(received47);EVENT_CODEC_COPY(received48);EVENT_CODEC_COPY(receivedOther);
    EVENT_CODEC_COPY(rejected46);EVENT_CODEC_COPY(rejected47);EVENT_CODEC_COPY(rejected48);EVENT_CODEC_COPY(rejectedOther);
    EVENT_CODEC_COPY(committed46);EVENT_CODEC_COPY(committed47);EVENT_CODEC_COPY(committed48);EVENT_CODEC_COPY(committedOther);
    EVENT_CODEC_COPY(lastCodecMessage);EVENT_CODEC_COPY(lastCodecError);EVENT_CODEC_COPY(last48RejectMask);EVENT_CODEC_COPY(seen48RejectMask);
#undef EVENT_CODEC_COPY
    const auto observer=LegacyPostObserver::counters();
    result.observerInstalled=observer.installed;result.captured=observer.captured;
    result.droppedShape=observer.droppedShape;result.droppedState=observer.droppedState;
    result.droppedFull=observer.droppedFull;result.droppedRegistry=observer.droppedRegistry;
    const auto install=LegacyPostObserver::installSnapshot();
    result.observerPhase=install.phase;result.observerPinStatus=install.pinStatus;
    result.observerContext=install.context;result.observerSymbolMask=install.symbolMask;
    result.observerCallShapeMask=install.callShapeMask;result.observerCallTargetMask=install.callTargetMask;
    result.observerRouteResult=install.routeResult;result.observerPatcherError=install.patcherError;
#endif
    return result;
}
void collectClient(IOUserClient *client) {
#ifdef AIRPORT_BRCM_EVENT_PIPE
    (void)eventPipes.collect(client);
#else
    (void)client;
#endif
}
void install(KernelPatcher &patcher,const Install &input) {
    if (attempted) return;attempted=true;
    auto set=[](Status value){__atomic_store_n(&state,static_cast<uint32_t>(value),__ATOMIC_RELEASE);};
    if (!input.registry || !input.runtimeBuild) {set(Status::Input);return;}
    if (!ScopedResetBridge::ready()) {set(Status::ResetUnavailable);return;}
    const auto prepared=input.registry->prepare();
    if (prepared!=ClientStatus::Passed && prepared!=ClientStatus::Duplicate) {set(Status::Input);return;}
    patcher.clearError();
    if (backend.initialize(reinterpret_cast<const void *>(input.brcmAddress),input.brcmSize,
                           reinterpret_cast<const void *>(input.legacyAddress),input.legacySize)!=VersionPinStatus::Passed) {
        set(Status::Pins);return;
    }
    const auto l=input.legacyAddress,b=input.brcmAddress;const auto ln=input.legacySize,bn=input.brcmSize;
#define PINL(name,offset,guard) pin(patcher,input.legacyIndex,name,l,ln,offset,guard)
#define PINB(name,offset,guard) pin(patcher,input.brcmIndex,name,b,bn,offset,guard)
    if (!PINL(NewName,0xb59ca,NewGuard) || !PINL(ExternalName,0xa6970,ExternalGuard) ||
        !PINL(AllocName,0xa6106,AllocGuard) || !PINL(InitName,0xa61c2,InitGuard) ||
        !PINL(StartName,0xa6488,StartGuard) || !PINL(VirtualTerminateName,0xb1fca,VirtualTerminateGuard) ||
        !PINL(WillTerminateName,0xb24b0,WillTerminateGuard) || !PINB(BrcmTerminateName,0x2e70c,BrcmTerminateGuard) ||
        !PINB(StopName,0x2db6a,StopGuard) || !span(l,ln,0x15cb00,sizeof(OSMetaClass)) ||
        patcher.solveSymbol(input.legacyIndex,MetaName,l,ln)!=l+0x15cb00) {set(Status::Pins);return;}
#undef PINL
#undef PINB
    // Immutable after publication. active() first acquires state==Ready,
    // which is released only after all routes and this getter are installed.
    runtimeBuildGate=input.runtimeBuild;
    registry=input.registry;meta=reinterpret_cast<const OSMetaClass *>(l+0x15cb00);
    allocate=reinterpret_cast<Alloc>(l+0xa6106);initialize=reinterpret_cast<Init>(l+0xa61c2);start=reinterpret_cast<Start>(l+0xa6488);
    getRole=reinterpret_cast<GetRole>(l+0xb0778);getBSDName=reinterpret_cast<GetBSDName>(l+0xb0872);
    KernelPatcher::RouteRequest earlyLegacy[] {
        {VirtualTerminateName,wrappedVirtualTerminate,originalVirtualTerminate},
        {WillTerminateName,wrappedWillTerminate,originalWillTerminate}
    };
    KernelPatcher::RouteRequest earlyBrcm[] {
        {BrcmTerminateName,wrappedBrcmTerminate,originalBrcmTerminate},
        {StopName,wrappedStop,originalStop}
    };
    KernelPatcher::RouteRequest externalRoute(ExternalName,wrappedExternal,originalExternal);
    KernelPatcher::RouteRequest newRoute(NewName,wrappedNew,originalNew);
    if (!patcher.routeMultiple(input.legacyIndex,earlyLegacy,2,l,ln) ||
        !patcher.routeMultiple(input.brcmIndex,earlyBrcm,2,b,bn) ||
        // Short only: Lilu copies the first7 complete PIC bytes. The following
        // conditional branch/RIP load must never be copied into a trampoline.
        // A rel32 reach failure remains failed; there is no long fallback.
        !patcher.routeMultipleShort(input.legacyIndex,&externalRoute,1,l,ln) ||
        !patcher.routeMultiple(input.legacyIndex,&newRoute,1,l,ln)) {set(Status::Routes);return;}
#ifdef AIRPORT_BRCM_EVENT_PIPE
    // Control readiness is separate. Partial event setup keeps query5 false;
    // no owned mapping or async dispatch is exposed until every route is live.
    // EVENT_INSTALL_BEGIN: actual cold-path fixture, not task/route authority.
    auto record=[](uint32_t &field,uint32_t value) {__atomic_store_n(&field,value,__ATOMIC_RELAXED);};
    record(eventCounters.installContext,(ml_at_interrupt_context()?1U:0U)|(ml_get_interrupts_enabled()?2U:0U));
    record(eventCounters.installStage,1);
    const auto preparedEvents=eventPipes.prepare(*registry,backend);
    record(eventCounters.routerPrepareResult,static_cast<uint32_t>(preparedEvents));
    bool events=preparedEvents==kIOReturnSuccess;
    if (events) {
        record(eventCounters.installStage,2);
        const auto preparedObserver=LegacyPostObserver::prepare();
        record(eventCounters.observerPrepareStatus,static_cast<uint32_t>(preparedObserver));
        events=preparedObserver==LegacyPostObserver::Status::Passed;
    }
    if (events) {
        record(eventCounters.installStage,3);
        const auto observed=LegacyPostObserver::install(patcher,input.legacyIndex,l,ln);
        record(eventCounters.observerInstallStatus,static_cast<uint32_t>(observed));
        events=observed==LegacyPostObserver::Status::Passed;
    }
    mach_vm_address_t memory=0;
    if (events) {
        record(eventCounters.installStage,4);
        memory=patcher.solveSymbol(KernelPatcher::KernelID,MemoryName);
        record(eventCounters.memorySymbolPresent,memory?1U:0U);events=memory!=0;
    }
    if (events) {
        record(eventCounters.installStage,5);
        const auto range=ScanKernelIdentity::verifyRunningKernelCodeRange(memory,sizeof(MemoryGuard));
        record(eventCounters.memoryRangeResult,static_cast<uint32_t>(range));events=range==0;
    }
    if (events) {
        record(eventCounters.installStage,6);
        events=!memcmp(reinterpret_cast<const void *>(memory),MemoryGuard,sizeof(MemoryGuard));
        record(eventCounters.memoryGuardMatched,events?1U:0U);
    }
    if (events) {
        record(eventCounters.installStage,7);
        // First9 complete PIC bytes, short-only rel32; never overwrite beyond
        // this11-byte function into the following symbol. Failure stays off.
        KernelPatcher::RouteRequest route(MemoryName,wrappedMemory,originalMemory);
        events=patcher.routeMultipleShort(KernelPatcher::KernelID,&route,1) && originalMemory;
        record(eventCounters.memoryRouteResult,events?1U:0U);
    }
    record(eventCounters.installPatcherError,static_cast<uint32_t>(patcher.getError()));
    if (events) record(eventCounters.installStage,8);
    __atomic_store_n(&eventRoutesInstalled,events,__ATOMIC_RELEASE);
    patcher.clearError();
    // EVENT_INSTALL_END
#endif
    set(Status::Ready);
}
} } // namespace AWDLKernel::NativeControlBridge
