#include "event_pipe_router.hpp"
#include <kern/task.h>
#include <machine/machine_routines.h>
namespace AWDLKernel { namespace {
bool sleepable() {return !ml_at_interrupt_context() && ml_get_interrupts_enabled();}
}
bool EventPipeRouter::prepared() const {
    return __atomic_load_n(&preparation_,__ATOMIC_ACQUIRE)==2;
}
bool EventPipeRouter::ready() const {
    if (!prepared()) return false;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    const bool admitted=!retiring_;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);return admitted;
}
IOReturn EventPipeRouter::prepare(ClientRegistry &registry,const DriverVersionBackend &backend) {
    if (!sleepable()) return kIOReturnNotReady;
    uint32_t expected=0;
    if (!__atomic_compare_exchange_n(&preparation_,&expected,1U,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==2 && registry_==&registry && backend_==&backend?kIOReturnSuccess:kIOReturnBusy;
    auto *lock=IOSimpleLockAlloc();
    if (!lock) {__atomic_store_n(&preparation_,0U,__ATOMIC_RELEASE);return kIOReturnNoMemory;}
    registry_=&registry;backend_=&backend;lock_=lock;
    __atomic_store_n(&preparation_,2U,__ATOMIC_RELEASE);return kIOReturnSuccess;
}
IOReturn EventPipeRouter::externalLease(IOUserClient *client,ClientWorkLease &lease,bool inGate) const {
    if (!prepared() || !sleepable()) return kIOReturnNotReady;
    if (registry_->acquire(client,lease)!=ClientStatus::Passed) return kIOReturnNotReady;
    if (lease.owner()!=current_task()) return kIOReturnNotPrivileged;
    if (!lease.workLoop() || lease.workLoop()->inGate()!=inGate) return kIOReturnNotReady;
    return kIOReturnSuccess;
}
EventPipeRouter::Slot *EventPipeRouter::latest(const ClientWorkLease &lease) {
    for (size_t n=MaximumSessions;n;--n) {
        auto &slot=slots_[n-1];
        if (slot.state!=State::Unused && slot.client==lease.client() && slot.generation==lease.generation())
            return &slot;
    }
    return nullptr;
}
IOReturn EventPipeRouter::closeSlot(Slot &slot) {
    // Slot addresses/keys never change after publication. No IRQ lock spans
    // observer/Session calls, IOKit virtuals, gate work, or reference release.
    slot.session.beginClose();
    // Session's exclusive closer owns its observer shutdown. A delayed old
    // close must not close a later same-UC cycle through a generic client key.
    // Its terminal Session.close() returns before touching any new observer.
    const auto result=slot.session.close();
    const bool closed=slot.session.phase()==EventPipeCore::Phase::Closed;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    if (closed) slot.state=State::Terminal;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    return result;
}
IOReturn EventPipeRouter::create(IOUserClient *client,const VersionCall &verification) {
    ClientWorkLease lease;
    auto result=externalLease(client,lease,false);if (result!=kIOReturnSuccess) return result;
    Slot *candidate=nullptr;
    // At most one retry: close an old Closing pipe, then reserve a new resident
    // object under the same lock that publishes the irreversible retiring bit.
    for (unsigned attempt=0;attempt<2;++attempt) {
        Slot *old=nullptr;
        auto irq=IOSimpleLockLockDisableInterrupt(lock_);
        if (retiring_) {
            IOSimpleLockUnlockEnableInterrupt(lock_,irq);return kIOReturnNotReady;
        }
        old=latest(lease);
        if (old && (old->state==State::Creating || old->state==State::Live)) {
            IOSimpleLockUnlockEnableInterrupt(lock_,irq);return kIOReturnBusy;
        }
        if (old && old->state==State::Closing) {
            IOSimpleLockUnlockEnableInterrupt(lock_,irq);
            result=closeSlot(*old);if (result!=kIOReturnSuccess) return result;
            continue;
        }
        for (auto &slot:slots_) if (slot.state==State::Unused) {candidate=&slot;break;}
        if (!candidate) {
            IOSimpleLockUnlockEnableInterrupt(lock_,irq);return kIOReturnNoResources;
        }
        candidate->client=lease.client();candidate->generation=lease.generation();
        candidate->provider=lease.provider();candidate->controller=lease.controller();
        candidate->state=State::Creating;
        IOSimpleLockUnlockEnableInterrupt(lock_,irq);break;
    }
    if (!candidate) return kIOReturnBusy;
    result=candidate->session.create(*registry_,client,*backend_,verification);
    const bool closed=candidate->session.phase()==EventPipeCore::Phase::Closed;
    bool accepted=false;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    if (closed) candidate->state=State::Terminal;
    else if (result==kIOReturnSuccess && candidate->state==State::Creating && !retiring_) {
        candidate->state=State::Live;accepted=true;
    } else candidate->state=State::Closing;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    if (accepted) return kIOReturnSuccess;
    if (!closed) closeSlot(*candidate);
    return result==kIOReturnSuccess?kIOReturnAborted:result;
}
IOReturn EventPipeRouter::destroy(IOUserClient *client) {
    ClientWorkLease lease;
    const auto result=externalLease(client,lease,false);if (result!=kIOReturnSuccess) return result;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    Slot *slot=latest(lease);
    const bool empty=!slot || slot->state==State::Terminal;
    if (!empty) slot->state=State::Closing;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    // Native selector4 destroys a pipe, never this UC's control registration.
    return empty?kIOReturnSuccess:closeSlot(*slot);
}
IOReturn EventPipeRouter::retainMemoryForType(IOUserClient *client,uint32_t type,
    IOOptionBits *options,IOMemoryDescriptor **memory) {
    if (options) *options=0;if (memory) *memory=nullptr;
    if (!options || !memory) return kIOReturnBadArgument;
    ClientWorkLease lease;
    const auto result=externalLease(client,lease,false);if (result!=kIOReturnSuccess) return result;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    Slot *slot=latest(lease);
    const bool admitted=!retiring_ && slot && slot->state==State::Live;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    return admitted?slot->session.retainMemoryForType(type,options,memory):kIOReturnNotOpen;
}
IOReturn EventPipeRouter::subscribeFromSuccessfulDispatch(IOUserClient *client,
    const IOExternalMethodArguments &arguments) {
    ClientWorkLease lease;
    const auto result=externalLease(client,lease,true);if (result!=kIOReturnSuccess) return result;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    Slot *slot=latest(lease);
    const bool admitted=!retiring_ && slot && slot->state==State::Live;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    if (!admitted) return kIOReturnNotOpen;
    // No result rewrite, lock, readiness/Closing recheck or fallible action
    // follows successful adoption. The enclosing genuine RPC must do likewise.
    return slot->session.subscribeFromSuccessfulDispatch(arguments);
}
void EventPipeRouter::mark(Key kind,const void *key) {
    if (!prepared() || !key) return;
    Slot *closing[MaximumSessions] {};size_t count=0;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    // TRUSTED owned lifecycle only. A conservative boot-long barrier also
    // catches create that acquired a registry lease before reserving its slot.
    retiring_=true;
    for (auto &slot:slots_) {
        const void *saved=kind==Key::Client?static_cast<void *>(slot.client):
            kind==Key::Provider?static_cast<void *>(slot.provider):static_cast<void *>(slot.controller);
        if (slot.state!=State::Unused && slot.state!=State::Terminal && saved==key) {
            slot.state=State::Closing;closing[count++]=&slot;
        }
    }
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    for (size_t n=0;n<count;++n) closing[n]->session.beginClose();
    ObserverHandle ignored;
    if (kind==Key::Client) LegacyPostObserver::beginClose(static_cast<IOUserClient *>(const_cast<void *>(key)),ignored);
    else if (kind==Key::Provider) LegacyPostObserver::beginCloseProvider(static_cast<IOService *>(const_cast<void *>(key)),ignored);
    else LegacyPostObserver::beginCloseController(static_cast<IOService *>(const_cast<void *>(key)));
}
void EventPipeRouter::markClientClosing(IOUserClient *client) {mark(Key::Client,client);}
void EventPipeRouter::markProviderClosing(IOService *provider) {mark(Key::Provider,provider);}
void EventPipeRouter::markControllerClosing(IOService *controller) {mark(Key::Controller,controller);}
IOReturn EventPipeRouter::collect(IOUserClient *client) {
    if (!prepared() || !sleepable()) return kIOReturnNotReady;
    ClientWorkLease lease;
    if (registry_->acquireClosing(client,lease)!=ClientStatus::Passed || !lease.workLoop())
        return kIOReturnNotReady;
    if (lease.workLoop()->inGate()) return kIOReturnBusy;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);
    Slot *slot=latest(lease);
    const bool empty=!slot || slot->state==State::Terminal;
    if (!empty) slot->state=State::Closing;
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    return empty?kIOReturnSuccess:closeSlot(*slot);
}
EventPipeRouter::Snapshot EventPipeRouter::snapshot() const {
    Snapshot result;if (!prepared()) return result;result.prepared=1;
    const EventPipeSession *sessions[MaximumSessions] {};size_t count=0;
    const auto irq=IOSimpleLockLockDisableInterrupt(lock_);result.retiring=retiring_;
    for (const auto &slot:slots_) if (slot.state!=State::Unused) {
        sessions[count++]=&slot.session;
        ++result.used;
        if (slot.state==State::Creating) ++result.creating;
        if (slot.state==State::Live) ++result.live;
        if (slot.state==State::Closing) ++result.closing;
        if (slot.state==State::Terminal) ++result.terminal;
    }
    IOSimpleLockUnlockEnableInterrupt(lock_,irq);
    // Session storage never moves/frees. Never nest the worker's IRQ lock
    // under the router lock; samples need not refer to one global instant.
    bool codecSelected=false,rejected48Selected=false;
    for (size_t n=count;n>0;--n) {
        const auto worker=sessions[n-1]->workerSnapshot();
        result.workerCallbacks+=worker.callbacks;result.workerCommitted+=worker.committed;
        result.workerDropped+=worker.dropped;result.workerFull+=worker.full;
        result.workerFaults+=worker.faults;result.workerQueued+=worker.queued;
        result.workerRunning+=worker.running;
        result.received46+=worker.received46;result.received47+=worker.received47;
        result.received48+=worker.received48;result.receivedOther+=worker.receivedOther;
        result.rejected46+=worker.rejected46;result.rejected47+=worker.rejected47;
        result.rejected48+=worker.rejected48;result.rejectedOther+=worker.rejectedOther;
        result.committed46+=worker.committed46;result.committed47+=worker.committed47;
        result.committed48+=worker.committed48;result.committedOther+=worker.committedOther;
        result.seen48RejectMask|=worker.seen48RejectMask;
        // Counts are modulo2^64. The saved message/error also preserve the
        // observation discriminator if an individual counter wraps to zero.
        if (!codecSelected && (worker.received46 || worker.received47 || worker.received48 ||
            worker.receivedOther || worker.lastCodecMessage || worker.lastCodecError)) {
            result.lastCodecMessage=worker.lastCodecMessage;result.lastCodecError=worker.lastCodecError;
            codecSelected=true;
        }
        if (!rejected48Selected && (worker.rejected48 || worker.last48RejectMask)) {
            result.last48RejectMask=worker.last48RejectMask;rejected48Selected=true;
        }
    }
    return result;
}
}
