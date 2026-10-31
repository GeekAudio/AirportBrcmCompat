// Portable bounded state only. NOT task/object authorization or an IOKit mock.
// Caller serializes every operation with one IRQ-safe external lock. Only the
// reserved buffer may be written outside the lock, until commit/abort returns.
#ifndef AIRPORT_AWDL_LEGACY_POST_OBSERVER_CORE_HPP
#define AIRPORT_AWDL_LEGACY_POST_OBSERVER_CORE_HPP
#include <stddef.h>
#include <stdint.h>
#include <string.h>
namespace AWDLKernel {
class EventPipeWorker; // Resident typed worker only; no callback/function pointer.
constexpr size_t ObserverSessions=8,ObserverQueue=16,ObserverBodyCapacity=2048,ObserverPeerBodySize=68;
struct ObserverHandle {uintptr_t client=0;uint64_t generation=0;};
struct ObserverBinding {
    uintptr_t client=0,provider=0,controller=0;
    uint64_t generation=0;
};
struct OwnedPostEvent {
    uint32_t message=0,length=0;
    uint8_t body[ObserverBodyCapacity] {};
};
struct ObserverDrain {uint32_t admitting=0,copying=0,queued=0,delivering=0;};
struct ObserverCapture {size_t cell=ObserverQueue;uint64_t sequence=0;ObserverHandle owner {};};
using ObserverDelivery=ObserverCapture;
enum class ObserverCoreStatus : uint32_t {
    Passed=0,Argument,Missing,Stale,Pending,Closing,Capacity,Duplicate,Full,
    Shape,Empty,Busy,Overflow,Retiring
};
inline bool observerPostShape(uintptr_t returnOffset,uint32_t message,const void *data,size_t length) {
    if (returnOffset==0xb3824) return message==46 && !data && !length;
    if (returnOffset==0x42c7a || returnOffset==0x6c653)
        return message==47 && data && length==ObserverPeerBodySize;
    if (returnOffset==0x3f20d) return message==48 && data && length>=88 && length<=ObserverBodyCapacity;
    return false; // Includes tail sites and generic/gated sources not yet pinned.
}
inline bool observerOwnedBody(const OwnedPostEvent &event) {
    if (event.message==46) {
        if (event.length) return false;
        for (auto byte:event.body) if (byte) return false;
        return true;
    }
    // 48 admission here proves SOURCE ENVELOPE ONLY, not frame/TLV validity.
    // The consumer MUST run the real awcm48_translate on this owned snapshot
    // before publishing any ring record; capture success is not codec success.
    if (event.message==48) {
        if (event.length<88 || event.length>ObserverBodyCapacity) return false;
        for (size_t n=event.length;n<ObserverBodyCapacity;++n) if (event.body[n]) return false;
        return true;
    }
    if (event.message!=47 || event.length!=ObserverPeerBodySize) return false;
    if (event.body[6] || event.body[7] || event.body[8]!=1 ||
        event.body[9] || event.body[10] || event.body[11]) return false;
    for (size_t n=12;n<ObserverBodyCapacity;++n) if (event.body[n]) return false;
    return true; // First six peer-address bytes remain opaque, never logged.
}
// The actual kernel wrapper uses this exact forwarding order. Capture must
// release all its locks/leases before returning; original is called once for
// every capture outcome and its result is returned without translation.
template<class Capture,class Original,class Provider>
inline auto observerForward(Capture capture,Original original,Provider provider,
    uintptr_t returnPC,uint32_t message,void *data,size_t length)
    -> decltype(original(provider,message,data,length)) {
    capture(provider,returnPC,message,data,length);
    return original(provider,message,data,length);
}
class LegacyPostObserverCore final {
    struct Session {ObserverBinding binding {};bool pending=false,closing=false,canceling=false;
        bool reopening=false,lifecycleRetired=false;
        EventPipeWorker *worker=nullptr,*closedWorker=nullptr;};
    enum class CellState : uint8_t {Free,Copying,Queued,Delivering};
    struct Cell {CellState state=CellState::Free;uint64_t sequence=0;ObserverHandle owner {};OwnedPostEvent event {};};
    Session sessions[ObserverSessions] {};
    Cell cells[ObserverQueue] {};
    uint64_t serial=0;
    bool retiring=false;
    Session *find(const ObserverHandle &h) {
        for (auto &s:sessions) if (s.binding.client==h.client && h.client &&
            s.binding.generation==h.generation && h.generation) return &s;
        return nullptr;
    }
    const Session *find(const ObserverHandle &h) const {
        return const_cast<LegacyPostObserverCore *>(this)->find(h);
    }
    static bool same(const ObserverHandle &a,const ObserverHandle &b) {
        return a.client==b.client && a.generation==b.generation;
    }
    Cell *cell(const ObserverCapture &t,CellState state) {
        if (t.cell>=ObserverQueue || !t.sequence) return nullptr;
        auto &c=cells[t.cell];
        return c.state==state && c.sequence==t.sequence && same(c.owner,t.owner)?&c:nullptr;
    }
    static void clear(Cell &c) {
        memset(&c.event,0,sizeof(c.event));c.state=CellState::Free;c.sequence=0;c.owner={};
    }
    void cancelQueued(const ObserverHandle &h) {
        for (auto &c:cells) if (c.state==CellState::Queued && same(c.owner,h)) clear(c);
    }
public:
    explicit LegacyPostObserverCore(uint64_t initialSequence=0):serial(initialSequence) {}
    ObserverCoreStatus reserve(const ObserverBinding &b,size_t &index,ObserverHandle &out) {
        index=ObserverSessions;out={};
        if (!b.client || !b.provider || !b.controller || !b.generation) return ObserverCoreStatus::Argument;
        if (retiring) return ObserverCoreStatus::Retiring;
        size_t vacant=ObserverSessions;
        for (size_t n=0;n<ObserverSessions;++n) {
            const auto &s=sessions[n];
            if (s.binding.client && (s.binding.client==b.client || s.binding.provider==b.provider))
                return ObserverCoreStatus::Duplicate;
            if (!s.binding.client && vacant==ObserverSessions) vacant=n;
        }
        if (vacant==ObserverSessions) return ObserverCoreStatus::Capacity;
        sessions[vacant]={b,true,false,false};index=vacant;out={b.client,b.generation};
        return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus activate(const ObserverHandle &h) {
        auto *s=find(h);if (!s) return ObserverCoreStatus::Stale;
        if (retiring || s->closing || s->canceling || s->reopening || s->lifecycleRetired) return ObserverCoreStatus::Closing;
        if (!s->pending) return ObserverCoreStatus::Duplicate;
        s->pending=false;return ObserverCoreStatus::Passed;
    }
    // Failed admissions only: reserve cancellation while its real registry
    // lease is released outside the lock, then erase. Active/Closing admitted
    // sessions are permanent tombstones, never erased by this component.
    ObserverCoreStatus cancelPending(const ObserverHandle &h) {
        auto *s=find(h);if (!s || !s->pending || s->reopening) return ObserverCoreStatus::Stale;
        s->closing=true;s->canceling=true;return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus eraseCanceled(const ObserverHandle &h) {
        auto *s=find(h);if (!s || !s->pending || !s->canceling || s->reopening) return ObserverCoreStatus::Stale;
        if (s->lifecycleRetired) {
            s->pending=false;s->canceling=false;return ObserverCoreStatus::Closing;
        }
        *s=Session{};return ObserverCoreStatus::Passed;
    }
    // Does NOT prove old worker/session close: the actual adapter invokes the
    // concrete old worker.canReplaceBinding outside the lock, with genuine
    // current registry/task/topology/GET43 checks, before activateReopen.
    ObserverCoreStatus reserveReopen(const ObserverBinding &b,size_t &index,
                                    ObserverHandle &out,EventPipeWorker *&oldWorker) {
        index=ObserverSessions;out={};oldWorker=nullptr;
        const ObserverHandle h{b.client,b.generation};auto *s=find(h);
        if (!s) return ObserverCoreStatus::Stale;
        if (retiring || s->lifecycleRetired) return ObserverCoreStatus::Retiring;
        if (s->binding.provider!=b.provider || s->binding.controller!=b.controller)
            return ObserverCoreStatus::Argument;
        if (!s->closing || s->pending || s->reopening || s->canceling || !s->closedWorker)
            return ObserverCoreStatus::Closing;
        ObserverDrain counts;const auto drained=drain(h,counts);
        if (drained!=ObserverCoreStatus::Passed) return drained;
        s->pending=true;s->reopening=true;s->canceling=false;
        index=static_cast<size_t>(s-sessions);out=h;oldWorker=s->closedWorker;
        return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus activateReopen(const ObserverHandle &h,EventPipeWorker *oldWorker) {
        auto *s=find(h);if (!s) return ObserverCoreStatus::Stale;
        if (retiring || s->lifecycleRetired || s->canceling) return ObserverCoreStatus::Closing;
        if (!s->pending || !s->reopening || !s->closing || s->worker ||
            !oldWorker || s->closedWorker!=oldWorker) return ObserverCoreStatus::Argument;
        // No producer entered Pending/Closing; drain must still be empty.
        for (const auto &c:cells) if (c.state!=CellState::Free && same(c.owner,h))
            return ObserverCoreStatus::Busy;
        s->pending=false;s->reopening=false;s->closing=false;
        s->closedWorker=nullptr; // The NEW cycle must actually bind its NEW worker.
        // Keep original registration generation and monotonically increasing
        // queue serial. Old work owns its old immutable closed Session only.
        return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus cancelReopen(const ObserverHandle &h) {
        auto *s=find(h);if (!s || !s->pending || !s->reopening) return ObserverCoreStatus::Stale;
        s->pending=false;s->reopening=false;s->canceling=false;s->closing=true;
        return ObserverCoreStatus::Passed; // Preserve old proof/registration/tombstone.
    }
    ObserverCoreStatus activeBinding(const ObserverHandle &h,ObserverBinding &out) const {
        out={};const auto *s=find(h);if (!s) return ObserverCoreStatus::Stale;
        if (retiring || s->lifecycleRetired || s->closing || s->canceling) return ObserverCoreStatus::Closing;
        if (s->pending) return ObserverCoreStatus::Pending;
        out=s->binding;return ObserverCoreStatus::Passed;
    }
    // State storage only. The real adapter first proves registry authorization,
    // captured gate/topology and this typed worker's immutable real handle.
    ObserverCoreStatus bindWorker(const ObserverHandle &h,EventPipeWorker *worker) {
        if (!worker) return ObserverCoreStatus::Argument;
        ObserverBinding ignored;const auto ready=activeBinding(h,ignored);
        if (ready!=ObserverCoreStatus::Passed) return ready;
        auto *s=find(h);if (s->worker) return ObserverCoreStatus::Duplicate;
        s->worker=worker;return ObserverCoreStatus::Passed;
    }
    EventPipeWorker *worker(const ObserverHandle &h) const {
        ObserverBinding ignored;if (activeBinding(h,ignored)!=ObserverCoreStatus::Passed) return nullptr;
        return find(h)->worker; // Borrow only: the actual worker is resident until reboot.
    }
    ObserverCoreStatus beginCloseClient(uintptr_t client,ObserverHandle &out) {
        out={};for (auto &s:sessions) if (client && s.binding.client==client) {
            if (s.worker) {s.closedWorker=s.worker;s.worker=nullptr;}
            if (s.reopening) s.canceling=true;
            s.closing=true;out={client,s.binding.generation};cancelQueued(out);return ObserverCoreStatus::Passed;
        }
        return ObserverCoreStatus::Missing;
    }
    ObserverCoreStatus beginCloseProvider(uintptr_t provider,ObserverHandle &out) {
        out={};for (auto &s:sessions) if (provider && s.binding.provider==provider) {
            s.lifecycleRetired=true;return beginCloseClient(s.binding.client,out);
        }
        return ObserverCoreStatus::Missing;
    }
    size_t beginCloseController(uintptr_t controller) {
        size_t count=0;for (auto &s:sessions) if (controller && s.binding.controller==controller) {
            s.lifecycleRetired=true;ObserverHandle h;beginCloseClient(s.binding.client,h);++count;
        }
        return count;
    }
    void retire() {
        retiring=true;for (auto &s:sessions) if (s.binding.client) {
            ObserverHandle h;beginCloseClient(s.binding.client,h);
        }
    }
    ObserverCoreStatus begin(uintptr_t provider,uintptr_t returnOffset,uint32_t message,
        const void *data,size_t length,ObserverCapture &out,ObserverBinding &binding) {
        out={};binding={};
        if (!observerPostShape(returnOffset,message,data,length)) return ObserverCoreStatus::Shape;
        if (retiring) return ObserverCoreStatus::Retiring;
        Session *s=nullptr;
        for (auto &candidate:sessions) if (provider && candidate.binding.provider==provider) {s=&candidate;break;}
        if (!s) return ObserverCoreStatus::Missing;
        if (s->closing || s->canceling) return ObserverCoreStatus::Closing;
        if (s->pending) return ObserverCoreStatus::Pending;
        size_t index=ObserverQueue;
        for (size_t n=0;n<ObserverQueue;++n) if (cells[n].state==CellState::Free) {index=n;break;}
        if (index==ObserverQueue) return ObserverCoreStatus::Full;
        if (serial==UINT64_MAX) return ObserverCoreStatus::Overflow;
        auto &c=cells[index];c.state=CellState::Copying;c.sequence=++serial;
        c.owner={s->binding.client,s->binding.generation};memset(&c.event,0,sizeof(c.event));
        c.event.message=message;c.event.length=static_cast<uint32_t>(length);
        out={index,c.sequence,c.owner};binding=s->binding;return ObserverCoreStatus::Passed;
    }
    uint8_t *buffer(const ObserverCapture &t) {auto *c=cell(t,CellState::Copying);return c?c->event.body:nullptr;}
    ObserverCoreStatus abort(const ObserverCapture &t) {
        auto *c=cell(t,CellState::Copying);if (!c) return ObserverCoreStatus::Stale;
        clear(*c);return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus commit(const ObserverCapture &t) {
        auto *c=cell(t,CellState::Copying);if (!c) return ObserverCoreStatus::Stale;
        auto *s=find(t.owner);
        if (!s || s->pending || s->closing || s->canceling || retiring) {
            clear(*c);return ObserverCoreStatus::Closing;
        }
        if (!observerOwnedBody(c->event)) {clear(*c);return ObserverCoreStatus::Shape;}
        c->state=CellState::Queued;return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus reserveTake(const ObserverHandle &h,const OwnedPostEvent *&out,ObserverDelivery &token) {
        out=nullptr;token={};auto *s=find(h);if (!s) return ObserverCoreStatus::Stale;
        if (s->closing || s->pending || s->canceling || retiring) return ObserverCoreStatus::Closing;
        Cell *first=nullptr;size_t index=ObserverQueue;
        for (size_t n=0;n<ObserverQueue;++n) if (cells[n].state==CellState::Queued &&
            same(cells[n].owner,h) && (!first || cells[n].sequence<first->sequence)) {first=&cells[n];index=n;}
        if (!first) return ObserverCoreStatus::Empty;
        first->state=CellState::Delivering;out=&first->event;
        token={index,first->sequence,first->owner};return ObserverCoreStatus::Passed;
    }
    // Portable convenience. The real adapter reserves under its lock, then
    // copies the stable Delivering event OUTSIDE that lock before returning.
    ObserverCoreStatus take(const ObserverHandle &h,OwnedPostEvent &out,ObserverDelivery &token) {
        memset(&out,0,sizeof(out));const OwnedPostEvent *source=nullptr;const auto s=reserveTake(h,source,token);
        if (s==ObserverCoreStatus::Passed) out=*source;return s;
    }
    ObserverCoreStatus finish(const ObserverDelivery &token) {
        auto *c=cell(token,CellState::Delivering);if (!c) return ObserverCoreStatus::Stale;
        clear(*c);return ObserverCoreStatus::Passed;
    }
    ObserverCoreStatus drain(const ObserverHandle &h,ObserverDrain &out) const {
        out={};const auto *s=find(h);if (!s) return ObserverCoreStatus::Stale;
        if (!s->closing) return ObserverCoreStatus::Argument;
        out.admitting=s->pending?1U:0U;
        for (const auto &c:cells) if (same(c.owner,h)) {
            if (c.state==CellState::Copying) ++out.copying;
            if (c.state==CellState::Queued) ++out.queued;
            if (c.state==CellState::Delivering) ++out.delivering;
        }
        return out.admitting || out.copying || out.queued || out.delivering?ObserverCoreStatus::Busy:ObserverCoreStatus::Passed;
    }
};
} // namespace AWDLKernel
#endif
