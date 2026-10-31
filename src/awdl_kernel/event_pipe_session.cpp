#include "event_pipe_session.hpp"
#include <kern/task.h>
#include <kern/clock.h>
#include <machine/machine_routines.h>
#include <string.h>
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
#include "baseline_trace.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#endif
namespace AWDLKernel { namespace {
bool sleepable() {return !ml_at_interrupt_context() && ml_get_interrupts_enabled();}
class Publisher final {
    bool *owned=nullptr;
public:
    explicit Publisher(bool &flag) {
        bool expected=false;
        if (__atomic_compare_exchange_n(&flag,&expected,true,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            owned=&flag;
    }
    ~Publisher() {if (owned) __atomic_store_n(owned,false,__ATOMIC_RELEASE);}
    bool valid() const {return owned!=nullptr;}
};
}
class EventPipeSession::Operation final {
    EventPipeCore *core=nullptr;
public:
    explicit Operation(EventPipeCore &candidate) {if (candidate.acquire()) core=&candidate;}
    ~Operation() {if (core) core->release();}
    bool valid() const {return core!=nullptr;}
};
struct EventPipeSession::CreateCall {
    EventPipeSession *pipe;
    const DriverVersionBackend *backend;
    const VersionCall *verification;
};
struct EventPipeSession::MemoryCall {
    EventPipeSession *pipe;
    uint32_t type;
    IOOptionBits *options;
    IOMemoryDescriptor **memory;
};
struct EventPipeSession::PublishCall {
    EventPipeSession *pipe;
    uint32_t message;
    const void *body;
    size_t length;
    awc_ring_notice notice {};
    awc_ring_error ring=AWC_RING_CLOSED;
};
AsyncNotificationOwner::Context EventPipeSession::context() const {
    return {owner_.client(),owner_.workLoop(),owner_.generation()};
}
bool EventPipeSession::activeInGate() const {
    if (!registry_ || !backend_ || !owner_.client() || !owner_.workLoop() ||
        !owner_.workLoop()->inGate() || owner_.gate()->getWorkLoop()!=owner_.workLoop() ||
        !owner_.gate()->isEnabled() || owner_.client()->isInactive() ||
        owner_.provider()->isInactive() || owner_.controller()->isInactive() ||
        owner_.client()->getProvider()!=owner_.provider() ||
        owner_.provider()->getProvider()!=owner_.controller() ||
        owner_.provider()->getWorkLoop()!=owner_.workLoop() ||
        owner_.controller()->getWorkLoop()!=owner_.workLoop()) return false;
    ClientWorkLease current;
    return registry_->acquire(owner_.client(),current)==ClientStatus::Passed &&
        current.generation()==owner_.generation() && current.provider()==owner_.provider() &&
        current.controller()==owner_.controller() && current.gate()==owner_.gate() &&
        current.workLoop()==owner_.workLoop() &&
        backend_->matchesProviderIdentity(owner_.controller(),owner_.provider());
}
IOReturn EventPipeSession::createAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<CreateCall *>(argument);auto &p=*c.pipe;
    if (p.core_.phase()!=EventPipeCore::Phase::Preparing ||
        p.owner_.owner()!=current_task() || !p.activeInGate()) return kIOReturnNotReady;
    const auto admitted=LegacyPostObserver::subscribe(*p.registry_,p.owner_.client(),
        *c.backend,*c.verification,p.observer_);
    if (admitted.status!=LegacyPostObserver::Status::Passed) return kIOReturnNotReady;
    p.observerBound_=true;
    return kIOReturnSuccess;
}
IOReturn EventPipeSession::bindWorkerAction(OSObject *,void *argument,void *,void *,void *) {
    auto &p=*static_cast<EventPipeSession *>(argument);
    if (p.core_.phase()!=EventPipeCore::Phase::Preparing ||
        p.owner_.owner()!=current_task() || !p.activeInGate() ||
        !p.worker_.matchesBinding(p.observer_)) return kIOReturnNotReady;
    return LegacyPostObserver::bindWorker(p.observer_,p.worker_)==LegacyPostObserver::Status::Passed
        ?kIOReturnSuccess:kIOReturnNotReady;
}
IOReturn EventPipeSession::create(ClientRegistry &registry,IOUserClient *client,
    const DriverVersionBackend &backend,const VersionCall &verification) {
    if (!sleepable()) return kIOReturnNotReady;
    if (!core_.beginCreate()) return kIOReturnBusy;
    IOReturn result=kIOReturnNotReady;
    const auto acquired=registry.acquire(client,owner_);
    if (acquired==ClientStatus::Passed) {
        registry_=&registry;backend_=&backend;
        if (owner_.owner()==current_task() && !owner_.workLoop()->inGate() &&
            owner_.gate()->getWorkLoop()==owner_.workLoop() && owner_.gate()->isEnabled()) {
            result=memory_.create();
            if (result==kIOReturnSuccess) {
                CreateCall call {this,&backend,&verification};
                result=owner_.workLoop()->runAction(createAction,owner_.controller(),&call);
                if (result==kIOReturnSuccess) result=worker_.prepare(*this,observer_);
                if (result==kIOReturnSuccess)
                    result=owner_.workLoop()->runAction(bindWorkerAction,owner_.controller(),this);
            }
        } else result=kIOReturnNotPrivileged;
    }
    if (core_.finishCreate(result==kIOReturnSuccess)) {
        // A producer kick while Preparing may have parked. Subscription is a
        // separate readiness boundary and also kicks, without consuming early
        // snapshots before an adopted wake right exists.
        (void)worker_.kickFromProducer(observer_);
        return kIOReturnSuccess;
    }
    // Concurrent close may have won after successful observer admission. Do not
    // publish this half-created pipe. Its resident record remains until close
    // can drain our own observer copy/operations; an error never force-frees it.
    if (result==kIOReturnSuccess) result=kIOReturnAborted;
    close();
    return result;
}
IOReturn EventPipeSession::memoryAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<MemoryCall *>(argument);auto &p=*c.pipe;
    if (p.core_.phase()!=EventPipeCore::Phase::Open || !p.activeInGate() ||
        p.owner_.owner()!=current_task()) return kIOReturnNotReady;
    return p.memory_.retainMemoryForType(c.type,c.options,c.memory);
}
IOReturn EventPipeSession::retainMemoryForType(uint32_t type,IOOptionBits *options,
    IOMemoryDescriptor **memory) {
    if (options) *options=0;
    if (memory) *memory=nullptr;
    if (!options || !memory) return kIOReturnBadArgument;
    Operation operation(core_);
    if (!operation.valid()) return kIOReturnNotOpen;
    if (!sleepable() || owner_.workLoop()->inGate() || owner_.owner()!=current_task())
        return kIOReturnNotPrivileged;
    MemoryCall call {this,type,options,memory};
    return owner_.workLoop()->runAction(memoryAction,owner_.controller(),&call);
}
IOReturn EventPipeSession::subscribeFromSuccessfulDispatch(const IOExternalMethodArguments &args) {
    Operation operation(core_);
    if (!operation.valid()) return kIOReturnNotOpen;
    if (!sleepable() || owner_.owner()!=current_task() || !activeInGate())
        return kIOReturnNotPrivileged;
    if (__atomic_load_n(&subscribed_,__ATOMIC_ACQUIRE)) return kIOReturnBusy;
    const auto result=notification_.adoptFromSuccessfulDispatch(context(),args);
    if (result!=kIOReturnSuccess) return result;
    __atomic_store_n(&subscribed_,true,__ATOMIC_RELEASE); // No fallible step after adoption.
    // Queued pre-subscription events now have a real wake right. A close may
    // race this IRQ-safe kick, but MIG must still see the adopted RPC succeed.
    (void)worker_.kickFromProducer(observer_);
    return kIOReturnSuccess;
}
IOReturn EventPipeSession::publishAction(OSObject *,void *argument,void *,void *,void *) {
    auto &c=*static_cast<PublishCall *>(argument);auto &p=*c.pipe;
    if (p.core_.phase()!=EventPipeCore::Phase::Open || !p.activeInGate() ||
        !__atomic_load_n(&p.subscribed_,__ATOMIC_ACQUIRE))
        return kIOReturnNotReady;
    static_assert(sizeof(clock_sec_t)==8 && sizeof(clock_usec_t)==4,"Pinned calendar ABI");
    clock_sec_t seconds=0;clock_usec_t microseconds=0;
    clock_get_calendar_microtime(&seconds,&microseconds);
    if (microseconds>=1000000) return kIOReturnError;
    awc_event_metadata metadata {};
    metadata.opaque_8=seconds;metadata.opaque_10=microseconds;metadata.message=c.message;
    // activeInGate just proved the actual pinned getter is exactly awdl0.
    // Native reader compares all16 bytes with its bound interface name.
    static const uint8_t bsd[16]={'a','w','d','l','0',0};
    memcpy(metadata.producer,bsd,sizeof(bsd));
    c.ring=p.memory_.publish(&metadata,c.body,c.length,&c.notice);
    if (c.ring==AWC_RING_OK || c.ring==AWC_RING_FULL) return kIOReturnSuccess;
    return kIOReturnError;
}
EventPipeSession::PublishResult EventPipeSession::drainOne() {
    PublishResult result;
    Operation operation(core_);
    if (!operation.valid()) return result;
    // Serialize the complete publish->notify sequence, not only ring writes.
    // Otherwise a second commit could see notification Busy after an earlier
    // wake was consumed and leave the second record with no future wake.
    Publisher publisher(publishing_);
    if (!publisher.valid()) {result.result=kIOReturnBusy;return result;}
    if (!sleepable() || owner_.workLoop()->inGate()) {
        result.result=kIOReturnBadArgument;return result;
    }
    // Capture can race the owner's subscribe RPC. Leave queued snapshots in
    // place until a real adopted notification right exists; subscription kicks
    // the worker again. This flag conveys readiness only, never authorization.
    if (!__atomic_load_n(&subscribed_,__ATOMIC_ACQUIRE)) return result;
    LegacyPostObserver::DeliveryLease delivery;
    const auto taken=LegacyPostObserver::take(observer_,source_,delivery);
    if (taken!=LegacyPostObserver::Status::Passed) {
        result.result=taken==LegacyPostObserver::Status::Empty?kIOReturnNotFound:kIOReturnNotReady;
        return result;
    }
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
    // The observer has already copied this message48 into its owned resident
    // snapshot. This bounded read-only baseline runs before the unchanged codec;
    // it cannot gate, rewrite, accept, or reject the original event path.
    if (ScanKernelIdentity::currentProfile()==ScanKernelIdentity::Profile::Build25G332 &&
        source_.message==AWCM48_ACTION_FRAME_RX)
        BaselineTrace::observeOwnedMessage48(source_.body,source_.length);
#endif
    result.message=source_.message;
    result.codecAttempted=1;
    awcm_context format {AWCM_LEGACY_1200_12_2B1,AWCM_NATIVE_25G241_1200_13_1,6};
    awcm_event event {};
    PublishCall call {this,source_.message,nullptr,0};
    if (source_.message==AWCM48_ACTION_FRAME_RX) {
        const auto diagnosed=awcm48_translate_diagnosed(&format,source_.message,
                            source_.body,source_.length,&actionFrame_);
        result.codecError=static_cast<uint32_t>(diagnosed.error);
        result.codecRejectMask=diagnosed.reject_mask;
        if (diagnosed.error!=AWCM_OK) {
            result.result=kIOReturnUnsupported;result.dropped=1;return result;
        }
        call.body=actionFrame_.body;call.length=actionFrame_.body_size;
    } else {
        result.codecError=static_cast<uint32_t>(awcm_translate(&format,source_.message,
                         source_.length?source_.body:nullptr,source_.length,&event));
        if (result.codecError!=AWCM_OK) {
            result.result=kIOReturnUnsupported;result.dropped=1;return result;
        }
        call.body=event.body;call.length=event.body_size;
    }
    result.result=owner_.workLoop()->runAction(publishAction,owner_.controller(),&call);
    if (result.result!=kIOReturnSuccess) {result.dropped=1;return result;}
    result.committed=call.ring==AWC_RING_OK;
    result.full=call.ring==AWC_RING_FULL;
    result.dropped=result.full;
    if (call.notice.notify_required) result.notification=notification_.notifyZeroArgs(context());
    // The observer's owned delivery and our operation cover the zero-arg send.
    // A full ring drops this bounded snapshot and requests drain; it is not an
    // acknowledgement. Neither a committed event nor a failed send is replayed.
    return result;
}
void EventPipeSession::beginClose() {core_.beginClose();worker_.beginClose();}
IOReturn EventPipeSession::close() {
    beginClose();
    if (core_.phase()==EventPipeCore::Phase::Closed) return kIOReturnSuccess;
    if (!sleepable()) return kIOReturnBusy;
    if (!core_.acquireCloser()) return kIOReturnBusy;
    if (owner_.client() && owner_.workLoop()->inGate()) {
        core_.finishClose(false);return kIOReturnBusy;
    }
    if (worker_.pollStopped()!=kIOReturnSuccess) {
        core_.finishClose(false);return kIOReturnBusy;
    }
    if (observerBound_) {
        const auto closed=LegacyPostObserver::beginClose(owner_.client(),observer_);
        ObserverDrain drain;
        if (closed!=LegacyPostObserver::Status::Passed ||
            LegacyPostObserver::pollDrain(observer_,drain)!=LegacyPostObserver::Status::Passed ||
            drain.admitting || drain.copying || drain.queued || drain.delivering) {
            core_.finishClose(false);return kIOReturnBusy;
        }
    }
    if (owner_.client()) {
        const auto result=notification_.close(context());
        if (result!=kIOReturnSuccess) {core_.finishClose(false);return result;}
    }
    __atomic_store_n(&subscribed_,false,__ATOMIC_RELEASE);
    memory_.destroy(); // Existing IOKit mappings retain their separate MD refs.
    owner_.release();registry_=nullptr;backend_=nullptr;
    core_.finishClose(true);
    return kIOReturnSuccess;
}
}
