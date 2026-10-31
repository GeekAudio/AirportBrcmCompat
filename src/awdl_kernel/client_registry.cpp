#include "client_registry.hpp"
#include <IOKit/IOWorkLoop.h>
#include <IOKit/network/IONetworkController.h>
#include <kern/task.h>
#include <machine/machine_routines.h>
#include <string.h>

namespace AWDLKernel { namespace {
bool sleepableContext() {return !ml_at_interrupt_context() && ml_get_interrupts_enabled();}
bool exactClass(IOService *value,const char *expected) {
    return value && value->getMetaClass() && !strcmp(value->getMetaClass()->getClassName(),expected);
}
bool pendingShape(IOUserClient *client,task_t owner) {
    if (!exactClass(client,"IO80211AsyncEventUserClient") || client->getMetaClass()->getClassSize()!=0x158 ||
        client->getProvider()) return false;
    const auto *bytes=reinterpret_cast<const uint8_t *>(client);
    uint32_t type=0;uintptr_t actualOwner=0,virtualProvider=0,primaryProvider=0;
    memcpy(&type,bytes+0xe0,sizeof(type));memcpy(&actualOwner,bytes+0xe8,sizeof(actualOwner));
    memcpy(&virtualProvider,bytes+0xf0,sizeof(virtualProvider));memcpy(&primaryProvider,bytes+0xf8,sizeof(primaryProvider));
    return type==2 && actualOwner==reinterpret_cast<uintptr_t>(owner) && !virtualProvider && !primaryProvider;
}
void dropReferences(const ClientPointers &p) {
    // No registry lock and no old controller gate may be held at final drain.
    reinterpret_cast<IOUserClient *>(p.client)->release();
    reinterpret_cast<IOService *>(p.provider)->release();
    reinterpret_cast<IOService *>(p.controller)->release();
    task_deallocate(reinterpret_cast<task_t>(p.task));
    reinterpret_cast<IOCommandGate *>(p.gate)->release();
    reinterpret_cast<IOWorkLoop *>(p.loop)->release();
}
} // namespace

ClientWorkLease::~ClientWorkLease() {release();}
ClientStatus ClientWorkLease::release() {
    return registry?registry->release(*this):ClientStatus::Missing;
}
ClientStatus ClientRegistry::prepare() {
    if (!sleepableContext()) return ClientStatus::Context;
    if (__atomic_load_n(&lock,__ATOMIC_ACQUIRE)) return ClientStatus::Duplicate;
    IOSimpleLock *candidate=IOSimpleLockAlloc();if (!candidate) return ClientStatus::Capacity;
    IOSimpleLock *expected=nullptr;
    if (!__atomic_compare_exchange_n(&lock,&expected,candidate,false,__ATOMIC_RELEASE,__ATOMIC_ACQUIRE)) {
        IOSimpleLockFree(candidate);return ClientStatus::Duplicate;
    }
    return ClientStatus::Passed;
}
ClientRegistrationResult ClientRegistry::registerClient(IOUserClient *client,task_t owner,
    IOService *controller,IOService *provider,const DriverVersionBackend &backend,
    const VersionCall &verification,ClientHandle &handle) {
    return registerValidated(client,owner,controller,provider,backend,verification,handle,false);
}
ClientRegistrationResult ClientRegistry::reserveClient(IOUserClient *client,task_t owner,
    IOService *controller,IOService *provider,const DriverVersionBackend &backend,
    const VersionCall &verification,ClientHandle &handle) {
    return registerValidated(client,owner,controller,provider,backend,verification,handle,true);
}
ClientRegistrationResult ClientRegistry::registerValidated(IOUserClient *client,task_t owner,
    IOService *controller,IOService *provider,const DriverVersionBackend &backend,
    const VersionCall &verification,ClientHandle &handle,bool pending) {
    handle={};ClientRegistrationResult result;
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) {result.status=ClientStatus::NotPrepared;return result;}
    if (!sleepableContext()) {result.status=ClientStatus::Context;return result;}
    if (!client || owner==TASK_NULL || owner!=current_task() || !controller || !provider)
        return result;
    if (!exactClass(client,"IO80211AsyncEventUserClient") || client->isInactive() ||
        (pending?!pendingShape(client,owner):client->getProvider()!=provider)) {result.status=ClientStatus::Object;return result;}
    // Does the actual typed read with real task entitlement and pinned object
    // identity checks. A successful call is NOT a lifecycle/quiescence proof.
    result.verification=backend.get43(owner,controller,provider,verification);
    if (result.verification.status!=VersionStatus::Passed) {
        result.status=ClientStatus::BackendRejected;return result;
    }
    IOWorkLoop *loop=controller->getWorkLoop();
    auto *network=OSDynamicCast(IONetworkController,controller);
    IOCommandGate *gate=network?network->getCommandGate():nullptr;
    if (!loop || !loop->inGate() || !gate || gate->getWorkLoop()!=loop || provider->getWorkLoop()!=loop ||
        client->isInactive() || (pending?!pendingShape(client,owner):client->getProvider()!=provider)) {
        result.status=ClientStatus::Object;return result;
    }
    // The caller already owns all these real objects. Balancing a failed
    // registration cannot release the caller's final references under its gate.
    client->retain();controller->retain();provider->retain();gate->retain();loop->retain();task_reference(owner);
    ClientPointers objects {reinterpret_cast<uintptr_t>(client),reinterpret_cast<uintptr_t>(owner),
        reinterpret_cast<uintptr_t>(controller),reinterpret_cast<uintptr_t>(provider),reinterpret_cast<uintptr_t>(gate),
        reinterpret_cast<uintptr_t>(loop)};
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    result.status=core.add(objects,handle,pending);
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    if (result.status!=ClientStatus::Passed) dropReferences(objects);
    return result;
}
ClientStatus ClientRegistry::admission(IOService *provider) {
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);if (!guard) return ClientStatus::NotPrepared;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto result=core.admission(reinterpret_cast<uintptr_t>(provider));
    IOSimpleLockUnlockEnableInterrupt(guard,state);return result;
}
ClientStatus ClientRegistry::activateClient(const ClientHandle &handle) {
    ClientWorkLease lease;
    auto result=acquireClosing(reinterpret_cast<IOUserClient *>(handle.client),lease);
    if (result!=ClientStatus::Passed) return result;
    if (lease.generation()!=handle.generation) return ClientStatus::Stale;
    if (!sleepableContext() || lease.owner()!=current_task() || !lease.workLoop()->inGate() ||
        lease.gate()->getWorkLoop()!=lease.workLoop() || !lease.gate()->isEnabled()) return ClientStatus::Context;
    auto *client=lease.client();const auto *bytes=reinterpret_cast<const uint8_t *>(client);
    uint32_t type=0;uintptr_t owner=0,v=0,p=0;
    if (!exactClass(client,"IO80211AsyncEventUserClient") || client->getMetaClass()->getClassSize()!=0x158 ||
        client->isInactive() || lease.provider()->isInactive() || lease.controller()->isInactive() ||
        client->getProvider()!=lease.provider() || lease.provider()->getProvider()!=lease.controller() ||
        lease.provider()->getWorkLoop()!=lease.workLoop() || lease.controller()->getWorkLoop()!=lease.workLoop())
        return ClientStatus::Object;
    memcpy(&type,bytes+0xe0,sizeof(type));memcpy(&owner,bytes+0xe8,sizeof(owner));
    memcpy(&v,bytes+0xf0,sizeof(v));memcpy(&p,bytes+0xf8,sizeof(p));
    if (type!=2 || owner!=reinterpret_cast<uintptr_t>(lease.owner()) ||
        v!=reinterpret_cast<uintptr_t>(lease.provider()) || p) return ClientStatus::Object;
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    result=core.activate(handle);IOSimpleLockUnlockEnableInterrupt(guard,state);return result;
}
ClientStatus ClientRegistry::acquire(IOUserClient *client,ClientWorkLease &lease) {
    if (lease.registry) return ClientStatus::Busy;
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return ClientStatus::NotPrepared;
    ClientSnapshot snapshot;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto status=core.acquire(reinterpret_cast<uintptr_t>(client),snapshot);
    if (status==ClientStatus::Passed) {
        lease.snapshot=snapshot;lease.registry=this;
    }
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    return status;
}
ClientStatus ClientRegistry::release(ClientWorkLease &lease) {
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard || lease.registry!=this) return ClientStatus::Argument;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto status=core.release(lease.snapshot.handle);
    // A failed/stale release never decrements a new generation. Fail closed:
    // any old unmatched inflight reference stays registered for investigation.
    lease.snapshot={};lease.registry=nullptr;
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    return status;
}
ClientStatus ClientRegistry::acquireClosing(IOUserClient *client,ClientWorkLease &lease) {
    if (lease.registry) return ClientStatus::Busy;
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return ClientStatus::NotPrepared;
    ClientSnapshot snapshot;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto status=core.acquireClosing(reinterpret_cast<uintptr_t>(client),snapshot);
    if (status==ClientStatus::Passed) {lease.snapshot=snapshot;lease.registry=this;}
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    return status;
}
ClientStatus ClientRegistry::beginClose(IOUserClient *client,ClientHandle &handle) {
    handle={};IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return ClientStatus::NotPrepared;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto status=core.beginClose(reinterpret_cast<uintptr_t>(client),handle);
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    return status;
}
ClientStatus ClientRegistry::beginCloseProvider(IOService *provider,ClientHandle &handle) {
    handle={};IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return ClientStatus::NotPrepared;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto status=core.beginCloseProvider(reinterpret_cast<uintptr_t>(provider),handle);
    IOSimpleLockUnlockEnableInterrupt(guard,state);return status;
}
size_t ClientRegistry::beginCloseController(IOService *controller) {
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return 0;
    const IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    const auto count=core.beginCloseController(reinterpret_cast<uintptr_t>(controller));
    IOSimpleLockUnlockEnableInterrupt(guard,state);return count;
}
ClientStatus ClientRegistry::finishClose(const ClientHandle &handle) {
    if (!sleepableContext()) return ClientStatus::Context;
    IOSimpleLock *guard=__atomic_load_n(&lock,__ATOMIC_ACQUIRE);
    if (!guard) return ClientStatus::NotPrepared;
    ClientSnapshot snapshot;
    IOInterruptState state=IOSimpleLockLockDisableInterrupt(guard);
    auto status=core.startFinish(handle,snapshot);
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    if (status!=ClientStatus::Passed) return status;
    // startFinish retained the registry's existing references while reserving
    // removal, so this real WorkLoop cannot disappear before the next lock.
    auto *loop=reinterpret_cast<IOWorkLoop *>(snapshot.objects.loop);
    if (loop->inGate()) {
        state=IOSimpleLockLockDisableInterrupt(guard);core.cancelFinish(handle);
        IOSimpleLockUnlockEnableInterrupt(guard,state);return ClientStatus::Context;
    }
    ClientPointers detached;
    state=IOSimpleLockLockDisableInterrupt(guard);
    status=core.completeFinish(handle,detached);
    IOSimpleLockUnlockEnableInterrupt(guard,state);
    if (status==ClientStatus::Passed) dropReferences(detached);
    return status;
}
} // namespace AWDLKernel
