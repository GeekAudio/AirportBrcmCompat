// Default-unwired, bounded resident routing. No IOUC hooks or readiness claim.
#ifndef AIRPORT_AWDL_EVENT_PIPE_ROUTER_HPP
#define AIRPORT_AWDL_EVENT_PIPE_ROUTER_HPP
#include "event_pipe_session.hpp"
#include <IOKit/IOLocks.h>
namespace AWDLKernel {
class EventPipeRouter final {
public:
    static constexpr size_t MaximumSessions=8;
    struct Snapshot {
        uint32_t prepared=0,retiring=0,used=0,creating=0,live=0,closing=0,terminal=0;
        // All used resident Sessions, including terminal history. Counter sums
        // are uint64 modulo2^64; queued/running are sums of <=8 bool states.
        // Independent worker samples are numeric observations, not an atomic
        // whole-router readiness/drain assertion.
        uint64_t workerCallbacks=0,workerCommitted=0,workerDropped=0,workerFull=0,workerFaults=0;
        uint32_t workerQueued=0,workerRunning=0;
        uint64_t received46=0,received47=0,received48=0,receivedOther=0;
        uint64_t rejected46=0,rejected47=0,rejected48=0,rejectedOther=0;
        uint64_t committed46=0,committed47=0,committed48=0,committedOther=0;
        // Each last* comes from the newest allocated resident slot with the
        // corresponding observation: any codec attempt for lastCodec*, a
        // rejected48 for last48RejectMask. This is NOT cross-worker temporal
        // ordering. Empty callbacks cannot create/overwrite an observation.
        uint32_t lastCodecMessage=0,lastCodecError=0,last48RejectMask=0,seen48RejectMask=0;
    };
    EventPipeRouter()=default;
    EventPipeRouter(const EventPipeRouter &)=delete;
    EventPipeRouter &operator=(const EventPipeRouter &)=delete;
    // Static/resident owner only. No destructor, unload/reclamation, or reuse.
    // Registry/backend and mapped image bindings remain immutable and alive.
    // Sleepable initialization outside every captured provider WL/gate.
    IOReturn prepare(ClientRegistry &,const DriverVersionBackend &);
    // Genuine owning-task RPC entries. create/destroy/map run outside captured
    // WL; subscribe is called in the real owner gate. No caller-supplied auth.
    IOReturn create(IOUserClient *,const VersionCall &preparedVerification);
    IOReturn destroy(IOUserClient *);
    IOReturn retainMemoryForType(IOUserClient *,uint32_t,IOOptionBits *,IOMemoryDescriptor **);
    // Final RPC MUST remain Success after this succeeds. No subsequent fallible
    // work or Closing recheck may turn an adopted MIG right into an error reply.
    IOReturn subscribeFromSuccessfulDispatch(IOUserClient *,const IOExternalMethodArguments &);
    // ONLY genuine owned original lifecycle calls these. The bridge must first
    // establish actual ownership (e.g. registry acquireClosing for reset), or
    // pin/exact-match its physical provider/controller. Foreign reset must NOT
    // call these. They irreversibly retire router admission for this boot,
    // compare only saved keys, then mark Sessions/observer OUTSIDE the IRQ lock.
    // Caller subsequently marks ClientRegistry Closing, then original once.
    void markClientClosing(IOUserClient *);
    void markProviderClosing(IOService *);
    void markControllerClosing(IOService *);
    // Trusted kernel lifecycle/cleanup owner ONLY, NEVER an external RPC auth
    // path. acquireClosing permits the genuine stop thread's different task.
    // Sleepable outside captured WL; nonwaiting, Busy retains resident state.
    IOReturn collect(IOUserClient *);
    // Router admission only. The bridge separately requires the real pinned
    // control/reset, observer and memory routes, and an explicit candidate build
    // before advertising selector5. This is not a physical-drain or AirDrop
    // success assertion. The finite resident budget can still be exhausted.
    bool ready() const;
    Snapshot snapshot() const;
private:
    enum class State:uint32_t {Unused,Creating,Live,Closing,Terminal};
    struct Slot {
        EventPipeSession session;
        IOUserClient *client=nullptr;
        IOService *provider=nullptr,*controller=nullptr;
        uint64_t generation=0;
        State state=State::Unused;
    };
    enum class Key {Client,Provider,Controller};
    uint32_t preparation_=0;
    IOSimpleLock *lock_=nullptr;
    ClientRegistry *registry_=nullptr;
    const DriverVersionBackend *backend_=nullptr;
    bool retiring_=false;
    Slot slots_[MaximumSessions];
    bool prepared() const;
    IOReturn externalLease(IOUserClient *,ClientWorkLease &,bool inGate) const;
    Slot *latest(const ClientWorkLease &); // IRQ lock held; keys only.
    IOReturn closeSlot(Slot &);           // Outside IRQ lock/captured WL.
    void mark(Key,const void *);
};
}
#endif
