#include "disassociate_kernel.hpp"
#include "cache_kernel.hpp"
#include "current_bss.hpp"
#include "bss_capture.hpp"
#include "disassociate_memory.hpp"
#include "disassociate_frame.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#include <IOKit/IOLocks.h>
#include <machine/machine_routines.h>
#include <string.h>

namespace LegacyWiFi { namespace DisassociateKernel { namespace {
namespace D = DisassociateChildContract;
namespace B = CurrentBSS;
namespace F = DisassociateFrame;
namespace C = BSSCapture;
static_assert(B::MaximumBeaconBodyBytes <= ScanKernelIdentity::MaxOwnedWiredRead,
              "current BSS body must fit the bounded no-fault reader");
using Admission = DisassociateAdmission::Admission;
using Setter = int (*)(void *, void *);
// The selected case ignores the disable result; preserve its native EAX value
// without treating it as completion evidence.
using Disable = int32_t (*)(void *, void *);
using FindCFG = void *(*)(void *, void *);
using Worker = int32_t (*)(void *, uint32_t, void *, void *);
using BSSInit4331 = void (*)(void *, void *, void *, void *, uint32_t, uint32_t);
using BSSInit43224 = void (*)(void *, void *, void *, uint32_t);
using ClearBSSID = uintptr_t (*)(void *);
using CfgMfree = void (*)(void *, void *);
using StateChange = int32_t (*)(void *);
using Sender4331 = void *(*)(void *, void *, const void *, void *, void *, uint32_t);
using Sender43224 = void *(*)(void *, void *, const void *, void *, uint32_t);
using Builder = void *(*)(void *, uint32_t, const void *, const void *, const void *, uint32_t, void **);
using PacketFree = void (*)(void *, void *, int);
using MbufData = void *(*)(void *);
using RecvParser = int32_t (*)(void *, void *, const void *, uint32_t,
                              const void *, uint32_t, void *);
using JoinComplete4331 = void (*)(void *, void *, void *, const void *, uint32_t);
using JoinComplete43224 = void (*)(void *, const void *, uint32_t);
struct Child {
    Admission admission {};
    Setter setter = nullptr;
    Disable disable = nullptr;
    Worker worker = nullptr;
    FindCFG findCFG = nullptr;
    BSSInit4331 bssInit4331 = nullptr;
    BSSInit43224 bssInit43224 = nullptr;
    ClearBSSID clearBSSID = nullptr;
    CfgMfree cfgMfree = nullptr, cfgFree = nullptr;
    void (*wlcStop)(void *) = nullptr;
    StateChange down = nullptr, detach = nullptr;
    Sender4331 sender4331 = nullptr;
    Sender43224 sender43224 = nullptr;
    Builder builder = nullptr;
    PacketFree packetFree = nullptr;
    MbufData mbufData = nullptr;
    RecvParser recvParser = nullptr;
    JoinComplete4331 joinComplete4331 = nullptr;
    JoinComplete43224 joinComplete43224 = nullptr;
    C::Registry capture;
    bool attempted = false;
    uint32_t active = 0;
    DisassociateMemory::State memory;
};
Child children[D::ChildCount];
API api {};
IOSimpleLock *scopeLock = nullptr;
IOSimpleLock *memoryLock = nullptr;
uint32_t configured = 0;
bool attempted = false;
uint64_t nextOperation = 1;
constexpr size_t ScopeCapacity = 8;
struct BuilderCall;

struct IdleObservation {
    uintptr_t wlc = 0, cfg = 0, association = 0;
};

struct Scope {
    uintptr_t thread = 0;
    void *controller = nullptr;
    void *interface = nullptr;
    CacheKernel::Lease *lease = nullptr;
    Child *child = nullptr;
    uint64_t operation = 0;
    uint64_t memoryEpoch = 0;
    uintptr_t wlc = 0, cfg = 0, record = 0;
    uintptr_t mappedCFG = 0;
    bool cfgMapped = false;
    bool setterSeen = false, setterActive = false;
    bool idleCaptured = false, idleCompleted = false;
    IdleObservation idle {};
    bool disableSeen = false, disableActive = false, workerSeen = false;
    bool workerActive = false;
    uint32_t reason = 0;
    bool enhanceRequested = false;
    F::RouteContext *frameContext = nullptr;
    DisassociateMemory::Ticket *frameMutation = nullptr;
    BuilderCall *builderCall = nullptr;
    void *frameOSL = nullptr;
    bool frameMatched = false, frameEnhanced = false, frameAccepted = false;
    bool failed = false;
    int failure = EOPNOTSUPP;
    B::OwnedSnapshot snapshot {};
    B::Binding binding {};
    B::CompletionToken completion;
    Scope *next = nullptr;
};
Scope *scopes = nullptr;

class Guard {
public:
    Guard() : restore(IOSimpleLockLockDisableInterrupt(scopeLock)) {}
    ~Guard() { IOSimpleLockUnlockEnableInterrupt(scopeLock, restore); }
    Guard(const Guard &) = delete;
    Guard &operator=(const Guard &) = delete;
private:
    IOInterruptState restore;
};
// Only bounded no-fault reads and counter updates occur under this lock. No
// native driver, allocator, provider lease or WorkLoop method may be called
// while it is held. Every admitted identity/body mutator registers before its
// native body and unregisters afterwards, without holding this lock across it.
// Unused metadata such as the separate DTIM byte is not an atomic snapshot
// contract; it never participates in the identity fingerprint or pruning.
class MemoryGuard {
public:
    MemoryGuard() : restore(IOSimpleLockLockDisableInterrupt(memoryLock)) {}
    ~MemoryGuard() { IOSimpleLockUnlockEnableInterrupt(memoryLock, restore); }
    MemoryGuard(const MemoryGuard &) = delete;
    MemoryGuard &operator=(const MemoryGuard &) = delete;
private:
    IOInterruptState restore;
};
bool safeThread() { return !ml_at_interrupt_context() && ml_get_interrupts_enabled(); }
bool active(const Child &child) { return __atomic_load_n(&child.active, __ATOMIC_ACQUIRE) != 0; }
int childIndex(Source source) {
    return source == Source::Pinned4331 ? 0 : source == Source::Pinned43224 ? 1 : -1;
}
Source childSource(const Child &child) {
    return child.admission.child == D::Brcm4331 ? Source::Pinned4331 : Source::Pinned43224;
}
class Mutation {
public:
    explicit Mutation(Child &owner, bool nestedClear = false) : child(owner) {
        // Capture thread/context before taking the lock: its acquisition
        // intentionally disables interrupts and must not change admission.
        const uintptr_t thread = api.currentThread();
        const bool nested = nestedClear && safeThread();
        MemoryGuard guard;
        child.memory.beginMutation(thread, nested, ticket);
        child.capture.clearPending();
    }
    ~Mutation() {
        MemoryGuard guard;
        child.memory.end(ticket);
    }
    Mutation(const Mutation &) = delete;
    Mutation &operator=(const Mutation &) = delete;
private:
    Child &child;
    DisassociateMemory::Ticket ticket;
};
bool addScope(Scope &scope) {
    Guard guard;
    size_t count = 0;
    for (auto *p = scopes; p; p = p->next) {
        if (++count >= ScopeCapacity || p->thread == scope.thread || p->interface == scope.interface)
            return false;
    }
    if (!nextOperation) return false;
    scope.operation = nextOperation;
    nextOperation = nextOperation == UINT64_MAX ? 0 : nextOperation + 1;
    scope.next = scopes;
    scopes = &scope;
    return true;
}
void removeScope(Scope &scope) {
    Guard guard;
    auto **link = &scopes;
    while (*link && *link != &scope) link = &(*link)->next;
    if (*link) *link = scope.next;
    scope.next = nullptr;
}
Scope *currentScope(Child &child) {
    if (!scopeLock || !active(child) || !safeThread()) return nullptr;
    const uintptr_t thread = api.currentThread();
    if (!thread) return nullptr;
    Guard guard;
    for (auto *p = scopes; p; p = p->next) {
        if (p->thread != thread) continue;
        if (p->child != &child) { p->failed = true; return nullptr; }
        // Only the same synchronous thread may borrow this stack scope. It
        // cannot return from perform/removeScope while executing this detour.
        return p;
    }
    return nullptr;
}
bool readAt(uintptr_t base, size_t offset, void *bytes, size_t size) {
    return base && offset <= UINTPTR_MAX - base &&
        ScanKernelIdentity::copyOwnedWiredMemory(base + offset, bytes, size);
}
bool readPointer(uintptr_t base, size_t offset, uintptr_t &out) {
    out = 0;
    return readAt(base, offset, &out, sizeof(out)) && out && out % alignof(uintptr_t) == 0;
}
// Called under MemoryGuard, with the operation's controller WorkLoop gate
// already established by its live CacheKernel lease. The gate serializes the
// ordinary ioctl/timer/receive paths; the main epoch additionally rejects the
// routed BSS replacement and teardown windows. No BSSID or body is needed:
// the sampled Tahoe FSM state0 (LINK_DOWN), on event4, ignores both reason and
// flush even if an old beacon remains cached. This is a local idle predicate,
// not a future reconnect ban.
bool readNativeIdle(Scope &scope, IdleObservation &observation) {
    const auto kind = scope.child->admission.child;
    const auto layout = D::currentBSSLayout(kind);
    uintptr_t wlc = 0, cfg = 0, association = 0;
    uint8_t ap = 0, associated = 0, alternate = 0;
    uint32_t type = 0, state = 0;
    if (!scope.child->memory.readable(scope.memoryEpoch) ||
        !readPointer(reinterpret_cast<uintptr_t>(scope.controller),
                     layout.controllerWLCOffset, wlc)) return false;
    if (kind == D::Brcm4331) {
        // Only the setter's exact native CfgFind call can supply this cfg.
        uintptr_t cfgWLC = 0;
        cfg = scope.mappedCFG;
        if (!scope.cfgMapped || !cfg || cfg % alignof(uintptr_t) ||
            !readPointer(cfg, 0, cfgWLC) || cfgWLC != wlc ||
            !readAt(cfg, 0x0a, &ap, sizeof(ap)) || ap ||
            !readAt(cfg, 0x0b, &associated, sizeof(associated)) || associated ||
            !readAt(cfg, 0x22, &alternate, sizeof(alternate)) || alternate ||
            !readPointer(cfg, 0x320, association) ||
            !readAt(association, 0x08, &type, sizeof(type)) || type ||
            !readAt(association, 0x0c, &state, sizeof(state)) || state) return false;
    } else {
        // This setter reads its WLC through +0x420, while the worker/stop
        // contract uses +0x418. Require both live slots to name the same WLC.
        uintptr_t setterWLC = 0;
        uint8_t staAssociated = 0, cfgAP = 0, infrastructure = 0;
        if (wlc > UINTPTR_MAX - 0xf10 ||
            !readPointer(reinterpret_cast<uintptr_t>(scope.controller), 0x420, setterWLC) ||
            setterWLC != wlc) return false;
        cfg = wlc + 0xf10;
        association = wlc;
        if (!readAt(wlc, 0x2f, &ap, sizeof(ap)) || ap ||
            !readAt(wlc, 0x3b, &associated, sizeof(associated)) || associated ||
            !readAt(wlc, 0x3a, &alternate, sizeof(alternate)) || alternate ||
            !readAt(cfg, 0x0a, &cfgAP, sizeof(cfgAP)) || cfgAP ||
            !readAt(wlc, 0x10e8, &staAssociated, sizeof(staAssociated)) || staAssociated ||
            // The native setter also calls setIBSS(false). Only an already
            // non-IBSS mode skips its separate down/up and mode configuration.
            !readAt(wlc, 0x263a, &infrastructure, sizeof(infrastructure)) || !infrastructure ||
            !readAt(wlc, 0x3798, &type, sizeof(type)) || type ||
            !readAt(wlc, 0x379c, &state, sizeof(state)) || state) return false;
    }
    observation = {wlc, cfg, association};
    return true;
}

void completeNativeIdle(Scope &scope, int setterResult) {
    if (setterResult || scope.failed || !scope.idleCaptured ||
        scope.disableSeen || scope.workerSeen || !scope.lease->current()) return;
    MemoryGuard guard;
    IdleObservation after;
    scope.idleCompleted = readNativeIdle(scope, after) &&
        after.wlc == scope.idle.wlc && after.cfg == scope.idle.cfg &&
        after.association == scope.idle.association;
}

bool disableCaller(const Child &child, uintptr_t caller) {
    const auto &image = child.admission.image;
    const size_t instruction = child.admission.child == D::Brcm4331 ? 0x332e7 : 0x68870;
    return image.base <= UINTPTR_MAX - instruction - 5 && caller == image.base + instruction + 5 &&
        ProviderContract::call(image, instruction, child.admission.symbols.addresses[D::Disable]);
}
bool bindDisable(Scope &scope, void *wlc, void *cfg, uintptr_t caller) {
    if (scope.failed || !scope.setterActive || scope.disableSeen || !wlc || !cfg ||
        !disableCaller(*scope.child, caller) || !scope.lease->current()) return false;
    MemoryGuard guard;
    if (!scope.child->memory.readable(scope.memoryEpoch)) return false;
    const auto layout = D::currentBSSLayout(scope.child->admission.child);
    uintptr_t current = 0;
    if (!readPointer(reinterpret_cast<uintptr_t>(scope.controller), layout.controllerWLCOffset, current) ||
        current != reinterpret_cast<uintptr_t>(wlc)) return false;
    const uintptr_t configuration = reinterpret_cast<uintptr_t>(cfg);
    uint8_t ap = 0;
    if (!readAt(configuration, 0x0a, &ap, sizeof(ap)) || ap) return false;
    if (scope.child->admission.child == D::Brcm4331) {
        uintptr_t cfgWLC = 0;
        if (!scope.cfgMapped || scope.mappedCFG != configuration ||
            !readPointer(configuration, 0, cfgWLC) || cfgWLC != current) return false;
    } else if (current > UINTPTR_MAX - 0xf10 || configuration != current + 0xf10) {
        return false;
    }
    scope.wlc = current;
    scope.cfg = configuration;
    return true;
}
struct RawSnapshot {
    uintptr_t record = 0;
    size_t recordSize = 0, bodySize = 0;
    uint8_t bytes[B::Record4331Size] {}, beaconBody[B::MaximumBeaconBodyBytes] {};
    bool recovered = false;
    B::OwnedSnapshot recoveredSnapshot {};
    ~RawSnapshot() {
        memset(bytes, 0, sizeof(bytes)); memset(beaconBody, 0, sizeof(beaconBody));
        memset(&recoveredSnapshot, 0, sizeof(recoveredSnapshot));
    }
};
int copyCurrentRecord(Scope &scope, RawSnapshot &raw) {
    const auto kind = scope.child->admission.child;
    const auto layout = D::currentBSSLayout(kind);
    uint8_t alternate = 0;
    uintptr_t record = 0;
    // The caller holds memoryLock, has rejected all active child mutators and
    // checked the epoch captured before the original SET22 call. The original
    // native stack supplies the WLC/cfg binding; the short read window prevents
    // a routed BSS replacement, IE release or teardown from entering midway.
    if (kind == D::Brcm4331) {
        if (!readAt(scope.cfg, 0x22, &alternate, 1) || alternate ||
            !readPointer(scope.cfg, layout.bsscfgCurrentBSSOffset, record)) return EOPNOTSUPP;
    } else {
        if (!readAt(scope.wlc, 0x3a, &alternate, 1) || alternate ||
            scope.wlc > UINTPTR_MAX - layout.inlineCurrentBSSOffset) return EOPNOTSUPP;
        record = scope.wlc + layout.inlineCurrentBSSOffset;
    }
    if (!readAt(record, 0, raw.bytes, layout.recordSize)) return EFAULT;
    const uintptr_t ie = ScanBridge::read64(raw.bytes + B::IEPointerOffset);
    const size_t length = ScanBridge::read16(raw.bytes + B::IELengthOffset);
    if (length > sizeof(raw.beaconBody)) return EOVERFLOW;
    if ((ie != 0) != (length != 0)) return EINVAL;
    if (length && (ie > UINTPTR_MAX - length ||
        !ScanKernelIdentity::copyOwnedWiredMemory(ie, raw.beaconBody, length))) return EFAULT;
    raw.record = record; raw.recordSize = layout.recordSize; raw.bodySize = length;
    if (!length && kind == D::Brcm4331)
        raw.recovered = scope.child->capture.lookup(scope.memoryEpoch,
            scope.wlc, scope.cfg, record, raw.bytes, raw.recordSize, &raw.recoveredSnapshot);
    return 0;
}
int decodeCurrentRecord(Scope &scope, const RawSnapshot &raw) {
    // Parsing touches only our owned stack copy, outside the interrupt-disabled
    // reader section. The selected mutation ticket protects the later scalar
    // check from any intervening native writer through its epoch.
    const int result = raw.recovered ? (scope.snapshot = raw.recoveredSnapshot, 0) :
        B::decode(childSource(*scope.child), raw.bytes, raw.recordSize,
                  raw.beaconBody, raw.bodySize, &scope.snapshot);
    if (result) return result;
    scope.record = raw.record;
    scope.binding.source = childSource(*scope.child);
    scope.binding.owner = scope.lease->key().manager;
    scope.binding.generation = scope.operation;
    scope.binding.thread = scope.thread;
    scope.binding.driver = reinterpret_cast<uintptr_t>(scope.controller);
    scope.binding.wlc = scope.wlc;
    scope.binding.cfg = scope.cfg;
    memcpy(scope.binding.bssid, scope.snapshot.bssid, B::BSSIDSize);
    return scope.completion.arm(scope.binding) ? 0 : EOPNOTSUPP;
}
int dispatchSetter(Child &child, void *controller, void *interface) {
    Scope *scope = currentScope(child);
    bool watched = false;
    if (scope) {
        watched = !scope->failed && !scope->setterSeen && scope->controller == controller &&
            scope->interface == interface && scope->lease->current();
        if (!watched) scope->failed = true;
        else { scope->setterSeen = true; scope->setterActive = true; }
    }
    if (watched && child.admission.child == D::Brcm43224) {
        MemoryGuard guard;
        scope->idleCaptured = readNativeIdle(*scope, scope->idle);
    }
    const int result = child.setter ? child.setter(controller, interface) : ENXIO;
    if (watched) {
        scope->setterActive = false;
        completeNativeIdle(*scope, result);
    }
    return result;
}
void *dispatchFindCFG(Child &child, void *wlc, void *wlcif, uintptr_t caller) {
    Scope *scope = currentScope(child);
    // The setter's own lookup binds the cfg to its input interface. The ioctl
    // dispatcher also uses this helper; that different caller is not a second
    // setter lookup and cannot grant or change this binding.
    const auto &image = child.admission.image;
    const bool setterLookup = scope && caller == image.base + 0xdaca &&
        ProviderContract::call(image, 0xdac5, child.admission.symbols.addresses[D::CfgFind]);
    bool watched = setterLookup && !scope->failed && scope->setterActive && !scope->cfgMapped &&
        scope->lease->current();
    if (watched) {
        MemoryGuard guard;
        uintptr_t nativeWLC = 0, nativeWLCIF = 0;
        watched = child.memory.readable(scope->memoryEpoch) &&
            readPointer(reinterpret_cast<uintptr_t>(scope->controller), 0x468, nativeWLC) &&
            readPointer(reinterpret_cast<uintptr_t>(scope->interface), 0x188, nativeWLCIF) &&
            nativeWLC == reinterpret_cast<uintptr_t>(wlc) && nativeWLCIF == reinterpret_cast<uintptr_t>(wlcif);
    }
    if (setterLookup && !watched) scope->failed = true;
    void *result = child.findCFG ? child.findCFG(wlc, wlcif) : nullptr;
    if (watched && !scope->failed) {
        if (!result || !scope->lease->current()) scope->failed = true;
        else {
            MemoryGuard guard;
            if (!child.memory.readable(scope->memoryEpoch)) scope->failed = true;
            else {
                scope->mappedCFG = reinterpret_cast<uintptr_t>(result);
                scope->cfgMapped = true;
                // Observe before returning to the native setter's associated
                // and AP tests. Its later local resets cannot forge pre-state.
                scope->idleCaptured = readNativeIdle(*scope, scope->idle);
            }
        }
    }
    return result;
}
int32_t dispatchDisable(Child &child, void *wlc, void *cfg, uintptr_t caller) {
    Scope *scope = currentScope(child);
    const bool watched = scope && bindDisable(*scope, wlc, cfg, caller);
    if (scope && !watched) scope->failed = true;
    if (watched) { scope->disableSeen = true; scope->disableActive = true; }
    const int32_t result = child.disable ? child.disable(wlc, cfg) : 0;
    if (watched) scope->disableActive = false;
    return result;
}

F::DriverKind frameDriver(const Child &child) {
    return child.admission.child == D::Brcm4331 ? F::DriverKind::Brcm4331 : F::DriverKind::Brcm43224;
}
struct SenderCall {
    Child *child;
    void *wlc, *arg1;
    const void *address3;
    void *arg3, *scb;
    uint32_t reason;
};
struct BuilderCall {
    Child *child;
    void *wlc;
    uint32_t subtype;
    const void *address1, *address2, *address3;
    void **bodyOut;
    void *osh;
    void *packet = nullptr;
    uint32_t bodyLength = 0;
};
bool frameCurrent(Scope &scope) {
    if (scope.failed || !scope.workerActive || !scope.frameContext || !scope.frameMutation ||
        !safeThread() || api.currentThread() != scope.thread || !scope.lease->current()) return false;
    MemoryGuard guard;
    return scope.child->memory.selectedReadable(*scope.frameMutation, scope.memoryEpoch);
}
uintptr_t frameThread(void *) { return safeThread() ? api.currentThread() : 0; }
bool frameOwnerCurrent(void *context, const void *owner, uint64_t request, uint64_t generation) {
    auto &scope = *static_cast<Scope *>(context);
    return owner == scope.lease->manager() && request == scope.operation &&
        generation == scope.lease->key().generation && frameCurrent(scope);
}
bool frameReadAddress(void *context, F::DriverKind driver, const void *address, F::MacAddress *out) {
    auto &scope = *static_cast<Scope *>(context);
    if (!out || driver != frameDriver(*scope.child) || !frameCurrent(scope)) return false;
    MemoryGuard guard;
    return scope.child->memory.selectedReadable(*scope.frameMutation, scope.memoryEpoch) &&
        readAt(reinterpret_cast<uintptr_t>(address), 0, out->bytes, sizeof(out->bytes));
}
void *frameOriginalSender(void *, const F::SenderInvocation &invocation) {
    auto &call = *static_cast<SenderCall *>(invocation.opaque);
    if (call.child->admission.child == D::Brcm4331)
        return call.child->sender4331 ? call.child->sender4331(call.wlc, call.arg1, call.address3,
                                                             call.arg3, call.scb, call.reason) : nullptr;
    return call.child->sender43224 ? call.child->sender43224(call.wlc, call.arg1, call.address3,
                                                           call.scb, call.reason) : nullptr;
}
void *frameOriginalBuilder(void *, const F::BuilderInvocation &invocation) {
    auto &call = *static_cast<BuilderCall *>(invocation.opaque);
    call.packet = nullptr;
    call.bodyLength = invocation.bodyLength;
    // Preserve the original full-width subtype and every address/stack argument.
    // Only the audited body length may be changed by the frame core.
    if (call.child->builder)
        call.packet = call.child->builder(call.wlc, call.subtype, call.address1, call.address2,
                                          call.address3, invocation.bodyLength, call.bodyOut);
    return call.packet;
}
bool frameWriteBody(void *context, F::DriverKind driver, void *slot, size_t offset,
                    const uint8_t *bytes, size_t length) {
    auto &scope = *static_cast<Scope *>(context);
    auto *call = scope.builderCall;
    if (!call || call->child != scope.child || !call->packet || !bytes ||
        driver != frameDriver(*scope.child) || slot != call->bodyOut ||
        call->wlc != reinterpret_cast<void *>(scope.wlc) ||
        call->bodyLength != F::ExtendedBodyBytes ||
        offset != F::ReasonIEAppendOffset || length != F::ReasonIEBytes || !frameCurrent(scope)) return false;
    // The admitted builder allocates/setlen(24 + bodyLength) and returns a
    // locally owned, unqueued mbuf. The public data accessor stays outside the
    // short child read lock. No packet ownership passes until this wrapper returns.
    const uintptr_t data = reinterpret_cast<uintptr_t>(call->child->mbufData(call->packet));
    constexpr size_t headerBytes = 24;
    constexpr size_t packetBytes = headerBytes + F::ExtendedBodyBytes;
    if (!data || data > UINTPTR_MAX - packetBytes || !frameCurrent(scope)) return false;
    uintptr_t body = 0;
    uint8_t ownedBytes[packetBytes] {};
    MemoryGuard guard;
    if (!scope.child->memory.selectedReadable(*scope.frameMutation, scope.memoryEpoch) ||
        !readAt(reinterpret_cast<uintptr_t>(slot), 0, &body, sizeof(body)) ||
        body != data + headerBytes || !readAt(data, 0, ownedBytes, sizeof(ownedBytes))) return false;
    // All fallible checks precede this write to the builder-owned writable
    // extent. The packet is private here, so no observer sees a partial IE.
    memcpy(reinterpret_cast<void *>(body + offset), bytes, length);
    memset(ownedBytes, 0, sizeof(ownedBytes));
    return true;
}
void frameFreeUnqueued(void *context, F::DriverKind driver, void *wlc, void *packet) {
    auto &scope = *static_cast<Scope *>(context);
    auto *call = scope.builderCall;
    if (!call || call->child != scope.child || driver != frameDriver(*scope.child) ||
        call->wlc != wlc || !packet || call->packet != packet || !call->osh) {
        scope.failed = true; scope.failure = EFAULT;
        return;
    }
    call->packet = nullptr; // Retire our local ownership before the native callback.
    // The admitted synchronous BSD ioctl holds its ifnet I/O reference until
    // this stack returns. Normal termination drains it before controller stop:
    // the pinned published-device detach path is stop_local -> wlcStop. This
    // barrier, not the controller retain or mutation epoch, keeps both OSL and
    // its WLC callback context alive after cache lease revocation. Never follow
    // WLC again here, and never free after returning to the native sender.
    call->child->packetFree(call->osh, packet, 1);
}
F::Callbacks frameCallbacks(Scope &scope) {
    F::Callbacks callbacks {};
    callbacks.context = &scope;
    callbacks.currentThread = frameThread;
    callbacks.ownerGenerationCurrent = frameOwnerCurrent;
    callbacks.readAddress3 = frameReadAddress;
    callbacks.originalSender = frameOriginalSender;
    callbacks.originalBuilder = frameOriginalBuilder;
    callbacks.writeBodyBytes = frameWriteBody;
    callbacks.freeUnqueuedPacket = frameFreeUnqueued;
    return callbacks;
}
void *dispatchSender(Child &child, void *wlc, void *arg1, const void *address3,
                     void *arg3, void *scb, uint32_t reason, uintptr_t caller) {
    SenderCall call {&child, wlc, arg1, address3, arg3, scb, reason};
    F::SenderInvocation invocation {};
    invocation.driver = frameDriver(child); invocation.callerReturnPC = caller;
    invocation.wlc = wlc; invocation.address3 = address3;
    invocation.scb = scb; invocation.reason = reason; invocation.opaque = &call;
    Scope *scope = currentScope(child);
    if (!scope || !scope->frameContext) return frameOriginalSender(nullptr, invocation);
    const auto result = F::interceptSender(*scope->frameContext, invocation, frameCallbacks(*scope));
    scope->frameMatched |= result.matched;
    scope->frameEnhanced |= result.extended;
    scope->frameAccepted |= result.matched && result.extended && result.packet &&
                            result.status == F::Status::Enhanced;
    return result.packet;
}
void *dispatchBuilder(Child &child, void *wlc, uint32_t subtype, const void *address1,
                      const void *address2, const void *address3, uint32_t bodyLength,
                      void **bodyOut, uintptr_t caller) {
    Scope *scope = currentScope(child);
    BuilderCall call {&child, wlc, subtype, address1, address2, address3, bodyOut,
                       scope ? scope->frameOSL : nullptr};
    F::BuilderInvocation invocation {};
    invocation.driver = frameDriver(child); invocation.callerReturnPC = caller;
    invocation.wlc = wlc; invocation.address3 = address3;
    // Unknown upper subtype bits cannot enter the narrow enhancing shape.
    invocation.subtype = subtype <= UINT16_MAX ? static_cast<uint16_t>(subtype) : 0;
    invocation.bodyLength = bodyLength; invocation.bodyOutSlot = bodyOut; invocation.opaque = &call;
    if (!scope || !scope->frameContext) return frameOriginalBuilder(nullptr, invocation);
    auto *previous = scope->builderCall;
    scope->builderCall = &call;
    const auto result = F::interceptBuilder(*scope->frameContext, invocation, frameCallbacks(*scope));
    scope->builderCall = previous;
    return result.packet;
}
F::HookContract frameContract(const Child &child) {
    auto contract = child.admission.child == D::Brcm4331 ? F::pinnedElCap4331Contract() :
                                                         F::pinnedElCap43224Contract();
    const auto &image = child.admission.image;
    for (size_t n = 0; n < contract.senderCallerPCCount; ++n) {
        const uintptr_t offset = contract.senderCallerPCs[n];
        if (offset < 5 || offset > UINTPTR_MAX - image.base ||
            !ProviderContract::call(image, offset - 5, child.admission.symbols.addresses[D::Sender])) return {};
        contract.senderCallerPCs[n] += image.base;
    }
    if (contract.builderReturnPC < 5 || contract.builderReturnPC > UINTPTR_MAX - image.base ||
        !ProviderContract::call(image, contract.builderReturnPC - 5,
                                child.admission.symbols.addresses[D::Builder])) return {};
    contract.builderReturnPC += image.base;
    return contract;
}
int32_t callWorker(Child &child, Scope *scope, DisassociateMemory::Ticket &mutation,
                   void *argument, uint32_t flag, void *callback, void *context) {
    if (!scope || !scope->enhanceRequested ||
        scope->snapshot.networkAssurance != NetworkAssurance::State::Enabled)
        return child.worker ? child.worker(argument, flag, callback, context) : -1;
    uintptr_t osh = 0;
    bool valid = false;
    {
        MemoryGuard guard;
        valid = child.memory.selectedReadable(mutation, scope->memoryEpoch) &&
            readPointer(scope->wlc, 8, osh);
    }
    if (!valid) {
        scope->failed = true; scope->failure = EFAULT;
        return child.worker ? child.worker(argument, flag, callback, context) : -1;
    }
    F::RouteContext routes;
    scope->frameContext = &routes; scope->frameMutation = &mutation;
    scope->frameOSL = reinterpret_cast<void *>(osh);
    F::MacAddress bssid {};
    memcpy(bssid.bytes, scope->snapshot.bssid, sizeof(bssid.bytes));
    F::RequestScope frame(routes, frameContract(child), frameDriver(child), scope->lease->manager(),
                          scope->operation, scope->lease->key().generation,
                          reinterpret_cast<void *>(scope->wlc), bssid, scope->reason, frameCallbacks(*scope));
    const int32_t result = child.worker ? child.worker(argument, flag, callback, context) : -1;
    const bool complete = frame.complete() && scope->frameMatched && scope->frameEnhanced && scope->frameAccepted;
    scope->frameContext = nullptr; scope->frameMutation = nullptr; scope->frameOSL = nullptr;
    if (!complete && !scope->failed) {
        scope->failed = true;
        scope->failure = frame.status() == F::Status::OwnerStale ? ESTALE : EIO;
    }
    return result;
}
int32_t dispatchWorker(Child &child, void *argument, uint32_t flag, void *callback,
                       void *context, uintptr_t caller) {
    Scope *scope = currentScope(child);
    bool watched = scope && !scope->failed && scope->setterActive && scope->disableActive &&
        !scope->workerSeen && scope->lease->current() &&
        D::workerCallerReturnPCMatches(child.admission.child, child.admission.image, caller) &&
        reinterpret_cast<uintptr_t>(argument) ==
            (child.admission.child == D::Brcm4331 ? scope->cfg : scope->wlc) &&
        flag == 1 && !callback && !context;
    B::WorkerTicket ticket {};
    DisassociateMemory::Ticket mutation;
    RawSnapshot raw;
    const uintptr_t thread = api.currentThread();
    if (scope && !watched) scope->failed = true;
    if (watched) {
        MemoryGuard guard;
        scope->workerSeen = true;
        scope->failure = child.memory.readable(scope->memoryEpoch) ? copyCurrentRecord(*scope, raw) : ESTALE;
        if (scope->failure) { scope->failed = true; watched = false; }
        else if (!child.memory.beginSelected(scope->memoryEpoch, scope->thread, mutation)) {
            scope->failed = true; scope->failure = ESTALE; watched = false;
        }
    }
    if (watched) {
        scope->failure = decodeCurrentRecord(*scope, raw);
        if (!scope->failure && scope->enhanceRequested &&
            scope->snapshot.networkAssurance == NetworkAssurance::State::Unknown)
            scope->failure = EOPNOTSUPP;
        if (scope->failure) { scope->failed = true; watched = false; }
        else {
            B::WorkerEntry entry {};
            entry.binding = scope->binding;
            entry.returnPCOffset = caller - child.admission.image.base;
            entry.arg0 = reinterpret_cast<uintptr_t>(argument);
            entry.arg1 = flag;
            memcpy(entry.liveBSSID, scope->snapshot.bssid, B::BSSIDSize);
            if (!scope->completion.workerEnter(entry, &ticket)) {
                scope->failed = true; scope->failure = EOPNOTSUPP; watched = false;
            }
        }
    }
    if (!watched) {
        MemoryGuard guard;
        if (mutation.active()) child.memory.end(mutation);
        child.memory.beginMutation(thread, false, mutation);
        child.capture.clearPending();
    }
    if (watched) scope->workerActive = true;
    const int32_t result = callWorker(child, watched ? scope : nullptr, mutation,
                                      argument, flag, callback, context);
    if (watched) scope->workerActive = false;
    // Lease checks take other locks and must stay outside the short read lock.
    const bool live = watched && !scope->failed && scope->lease->current();
    {
        MemoryGuard guard;
        if (watched && !scope->failed) {
            B::WorkerExit exit {};
            exit.binding = scope->binding;
            exit.status = result;
            bool read = live && child.memory.selectedReadable(mutation, scope->memoryEpoch) &&
                readAt(scope->record, 0, exit.liveBSSID, B::BSSIDSize);
            if (read && child.admission.child == D::Brcm43224)
                read = readAt(scope->record, B::IEPointerOffset, &exit.currentIEPointer, sizeof(exit.currentIEPointer)) &&
                       readAt(scope->record, B::IELengthOffset, &exit.currentIELength, sizeof(exit.currentIELength));
            // Do not follow an IE pointer after the native worker. All fields
            // read here belong to the fixed record, protected from replacement
            // and teardown until this short reader section ends.
            if (!read || !scope->completion.workerReturn(ticket, exit)) {
                scope->failed = true;
                scope->failure = result ? EIO : ESTALE;
            }
        }
        child.memory.end(mutation);
    }
    return result;
}
#define CHILD_ROUTES(suffix, index) \
__attribute__((noinline)) int setter##suffix(void *c, void *i) { return dispatchSetter(children[index], c, i); } \
__attribute__((noinline)) int32_t disable##suffix(void *w, void *c) { \
    return dispatchDisable(children[index], w, c, reinterpret_cast<uintptr_t>(__builtin_return_address(0))); } \
__attribute__((noinline)) int32_t worker##suffix(void *a, uint32_t b, void *c, void *d) { \
    return dispatchWorker(children[index], a, b, c, d, reinterpret_cast<uintptr_t>(__builtin_return_address(0))); }
CHILD_ROUTES(4331, 0)
CHILD_ROUTES(43224, 1)
#undef CHILD_ROUTES
__attribute__((noinline)) void *sender4331(void *w, void *a, const void *b, void *c, void *s, uint32_t r) {
    return dispatchSender(children[0], w, a, b, c, s, r,
                          reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}
__attribute__((noinline)) void *sender43224(void *w, void *a, const void *b, void *s, uint32_t r) {
    return dispatchSender(children[1], w, a, b, nullptr, s, r,
                          reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}
#define BUILDER_ROUTE(suffix, index) \
__attribute__((noinline)) void *builder##suffix(void *w, uint32_t s, const void *a, const void *b, \
                                               const void *c, uint32_t n, void **out) { \
    return dispatchBuilder(children[index], w, s, a, b, c, n, out, \
                           reinterpret_cast<uintptr_t>(__builtin_return_address(0))); }
BUILDER_ROUTE(4331, 0)
BUILDER_ROUTE(43224, 1)
#undef BUILDER_ROUTE
__attribute__((noinline)) void *findCFG4331(void *w, void *i) {
    return dispatchFindCFG(children[0], w, i, reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}
// The guarded recvctl parser call dominates the refresh BSSInit call. The
// parser writes its caller's stack record, not the current target. Keep only
// owned bytes across that interval; an unrelated/nested parser replaces the
// same-thread pending token without invalidating an unchanged current BSS.
int32_t dispatchRecvParser(Child &child, void *wlc, void *rx, const void *bssid,
                          uint32_t flag, const void *body, uint32_t length,
                          void *output, uintptr_t caller) {
    const uintptr_t thread = api.currentThread();
    const uintptr_t address = reinterpret_cast<uintptr_t>(bssid);
    const uintptr_t cfg = address >= 0xf0 ? address - 0xf0 : 0;
    const auto &image = child.admission.image;
    const bool exact = active(child) && child.admission.child == D::Brcm4331 &&
        safeThread() && thread && wlc && rx && cfg && cfg % alignof(uintptr_t) == 0 &&
        output && body && flag == 1 && length >= B::BeaconFixedBodyBytes &&
        length <= B::MaximumBeaconBodyBytes && image.base <= UINTPTR_MAX - 0x46c80 &&
        caller == image.base + 0x46c80 &&
        ProviderContract::call(image, 0x46c7b, child.admission.symbols.addresses[D::RecvParser]);
    C::Ticket pending;
    uint64_t epoch = 0;
    struct OwnedInput {
        uint8_t record[B::Record4331Size] {}, body[B::MaximumBeaconBodyBytes] {};
        ~OwnedInput() { memset(record, 0, sizeof(record)); memset(body, 0, sizeof(body)); }
    } owned;
    bool copied = false;
    {
        MemoryGuard guard;
        if (thread) child.capture.invalidate(thread);
        else child.capture.clearPending();
        uintptr_t cfgWLC = 0;
        if (exact && (epoch = child.memory.snapshotEpoch()) &&
            readPointer(cfg, 0, cfgWLC) && cfgWLC == reinterpret_cast<uintptr_t>(wlc) &&
            child.capture.begin(thread, pending))
            copied = readAt(reinterpret_cast<uintptr_t>(body), 0, owned.body, length);
    }
    const int32_t result = child.recvParser ?
        child.recvParser(wlc, rx, bssid, flag, body, length, output) : -1;
    bool parsed = false;
    if (copied && result == 0) {
        MemoryGuard guard;
        parsed = child.memory.readable(epoch) &&
            readAt(reinterpret_cast<uintptr_t>(output), 0, owned.record, sizeof(owned.record));
    }
    B::OwnedSnapshot snapshot {};
    bool staged = false;
    if (parsed && !C::decodeProduced4331(owned.record, sizeof(owned.record),
                                        owned.body, length, &snapshot)) {
        MemoryGuard guard;
        if (child.memory.readable(epoch))
            staged = child.capture.stage(pending, epoch, reinterpret_cast<uintptr_t>(wlc), cfg,
                reinterpret_cast<uintptr_t>(output), owned.record, sizeof(owned.record), snapshot);
    }
    if (!staged) {
        MemoryGuard guard;
        child.capture.cancel(pending);
    }
    memset(&snapshot, 0, sizeof(snapshot));
    return result;
}
__attribute__((noinline)) int32_t recvParser4331(void *w, void *rx, const void *bssid,
        uint32_t flag, const void *body, uint32_t length, void *output) {
    return dispatchRecvParser(children[0], w, rx, bssid, flag, body, length, output,
                              reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}

void dispatchBSSInit4331(Child &child, void *w, void *source, void *cfg,
                         void *data, uint32_t a, uint32_t b, uintptr_t caller) {
    const uintptr_t thread = api.currentThread();
    const uintptr_t configuration = reinterpret_cast<uintptr_t>(cfg);
    const auto &image = child.admission.image;
    const bool exact = active(child) && child.admission.child == D::Brcm4331 &&
        safeThread() && thread && w && source && cfg && !data && a == 0x200 && b == 0 &&
        image.base <= UINTPTR_MAX - 0x46ce0 && caller == image.base + 0x46ce0 &&
        ProviderContract::call(image, 0x46cdb, child.admission.symbols.addresses[D::BSSInit]);
    DisassociateMemory::Ticket mutation;
    uint64_t publication = 0;
    uintptr_t target = 0;
    uint8_t record[B::Record4331Size] {};
    C::Fingerprint expected {};
    B::OwnedSnapshot snapshot {};
    bool selected = false;
    {
        MemoryGuard guard;
        child.memory.beginMutation(thread, false, mutation);
        publication = child.memory.mutationEpoch(mutation);
        uintptr_t cfgWLC = 0;
        selected = exact && publication > 1 &&
            readPointer(configuration, 0, cfgWLC) && cfgWLC == reinterpret_cast<uintptr_t>(w) &&
            readPointer(configuration, 0x318, target) && target != reinterpret_cast<uintptr_t>(source) &&
            readAt(reinterpret_cast<uintptr_t>(source), 0, record, sizeof(record)) &&
            C::fingerprint(record, sizeof(record), &expected) &&
            child.capture.take(thread, publication - 1, reinterpret_cast<uintptr_t>(w),
                configuration, reinterpret_cast<uintptr_t>(source), record, sizeof(record), &snapshot);
        // This writer advanced the child generation. Other staged rows now
        // describe an earlier generation and must not occupy pending slots.
        child.capture.clearPending();
    }
    if (child.bssInit4331) child.bssInit4331(w, source, cfg, data, a, b);
    {
        MemoryGuard guard;
        uintptr_t current = 0;
        C::Fingerprint actual {};
        if (selected && child.memory.mutationEpoch(mutation) == publication &&
            readPointer(configuration, 0x318, current) && current == target &&
            readAt(current, 0, record, sizeof(record)) &&
            C::fingerprint(record, sizeof(record), &actual) &&
            C::sameFingerprint(expected, actual))
            child.capture.publish(publication, reinterpret_cast<uintptr_t>(w), configuration,
                current, record, sizeof(record), snapshot);
        // Publish and finish the ticket atomically. A later writer invalidates
        // this exact generation before any worker can use the owned value.
        child.memory.end(mutation);
    }
    memset(record, 0, sizeof(record)); memset(&snapshot, 0, sizeof(snapshot));
    memset(&expected, 0, sizeof(expected));
}
__attribute__((noinline)) void bssInit4331(void *w, void *source, void *cfg, void *data, uint32_t a, uint32_t b) {
    dispatchBSSInit4331(children[0], w, source, cfg, data, a, b,
                       reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}
void bssInit43224(void *w, void *source, void *cfg, uint32_t flag) {
    auto &child = children[1];
    Mutation mutation(child);
    if (child.bssInit43224) child.bssInit43224(w, source, cfg, flag);
}
void joinComplete4331(void *cfg, void *input, void *rx,
                      const void *body, uint32_t length) {
    auto &child = children[0];
    // JoinComplete may call BSSInit and then replace the current body's
    // allocation itself. Keep the outer writer active through that later
    // replacement; a nested BSSInit cannot publish an intermediate snapshot.
    Mutation mutation(child);
    if (child.joinComplete4331) child.joinComplete4331(cfg, input, rx, body, length);
}
void joinComplete43224(void *wlc, const void *body, uint32_t length) {
    auto &child = children[1];
    Mutation mutation(child);
    if (child.joinComplete43224) child.joinComplete43224(wlc, body, length);
}
uintptr_t dispatchClearBSSID4331(void *cfg, uintptr_t caller) {
    auto &child = children[0];
    auto *scope = currentScope(child);
    const auto &image = child.admission.image;
    // The ordinary worker and its clear-hardware-association helper clear the
    // same cfg. Other callers, another cfg, and interrupt reentry invalidate
    // the observation even if they happen to run on the same thread.
    const bool sameWorker = scope && scope->workerActive && !scope->failed &&
        scope->cfg == reinterpret_cast<uintptr_t>(cfg) &&
        ((caller == image.base + 0xb0fd6 &&
          ProviderContract::call(image, 0xb0fd1, child.admission.symbols.addresses[D::ClearBSSID])) ||
         (caller == image.base + 0xb0a0b &&
          ProviderContract::call(image, 0xb0a06, child.admission.symbols.addresses[D::ClearBSSID])));
    Mutation mutation(child, sameWorker);
    return child.clearBSSID ? child.clearBSSID(cfg) : 0;
}
__attribute__((noinline)) uintptr_t clearBSSID4331(void *cfg) {
    return dispatchClearBSSID4331(cfg, reinterpret_cast<uintptr_t>(__builtin_return_address(0)));
}
void cfgMfree4331(void *allocator, void *cfg) {
    auto &child = children[0];
    Mutation mutation(child);
    if (child.cfgMfree) child.cfgMfree(allocator, cfg);
}
void cfgFree4331(void *wlc, void *cfg) {
    auto &child = children[0];
    // The native outer free clears the published cfg-table entry only after
    // mfree returns. Keep a writer active through that unlink, not just until
    // the allocation itself has been released.
    Mutation mutation(child);
    if (child.cfgFree) child.cfgFree(wlc, cfg);
}
void wlcStop4331(void *controller) {
    auto &child = children[0];
    Mutation mutation(child);
    if (child.wlcStop) child.wlcStop(controller);
}
void wlcStop43224(void *controller) {
    auto &child = children[1];
    // Both native stops clear controller->WLC after detach has freed WLC.
    // Cover the entire publication transition before admitting a new scope.
    Mutation mutation(child);
    if (child.wlcStop) child.wlcStop(controller);
}
int32_t down43224(void *wlc) {
    auto &child = children[1];
    Mutation mutation(child);
    return child.down ? child.down(wlc) : -1;
}
int32_t detach4331(void *wlc) {
    auto &child = children[0];
    Mutation mutation(child);
    return child.detach ? child.detach(wlc) : -1;
}
int32_t detach43224(void *wlc) {
    auto &child = children[1];
    Mutation mutation(child);
    return child.detach ? child.detach(wlc) : -1;
}

int pruneError(SelectiveCache::Status status) {
    using S = SelectiveCache::Status;
    switch (status) {
    case S::Ok: return 0;
    case S::CapacityExceeded: case S::NodeLimitExceeded: return EOVERFLOW;
    case S::Stale: case S::AccessFailure: return ESTALE;
    case S::InvalidIdentity: return EINVAL;
    default: return EOPNOTSUPP;
    }
}
} // namespace

bool initialize(const API &callbacks) {
    if (attempted || !callbacks.classify || !callbacks.currentThread ||
        !callbacks.allocate || !callbacks.deallocate) return false;
    attempted = true;
    api = callbacks;
    scopeLock = IOSimpleLockAlloc();
    if (!scopeLock) return false;
    memoryLock = IOSimpleLockAlloc();
    if (!memoryLock) return false;
    __atomic_store_n(&configured, 1U, __ATOMIC_RELEASE);
    return true;
}
bool ready(Source source) {
    const int index = childIndex(source);
    return __atomic_load_n(&configured, __ATOMIC_ACQUIRE) && index >= 0 && active(children[index]);
}
bool installChild(KernelPatcher &patcher, const Admission &admission) {
    if (!__atomic_load_n(&configured, __ATOMIC_ACQUIRE) || !admission.ready ||
        (admission.child != D::Brcm4331 && admission.child != D::Brcm43224)) return false;
    auto &child = children[admission.child];
    if (child.attempted) return false;
    child.attempted = true;
    child.admission = admission;
    child.packetFree = reinterpret_cast<PacketFree>(admission.symbols.addresses[D::PktFree]);
    child.mbufData = reinterpret_cast<MbufData>(admission.imports.addresses[D::MbufData]);
    if (!child.packetFree || !child.mbufData) return false;
    const bool first = admission.child == D::Brcm4331;
    KernelPatcher::RouteRequest routes[] = {
        {D::Functions[admission.child][D::Builder].symbol, first ? builder4331 : builder43224, child.builder},
        {first ? D::Functions[0][D::Sender].symbol : nullptr, sender4331, child.sender4331},
        {first ? nullptr : D::Functions[1][D::Sender].symbol, sender43224, child.sender43224},
        {first ? D::Functions[0][D::RecvParser].symbol : nullptr, recvParser4331, child.recvParser},
        {first ? D::Functions[0][D::JoinComplete].symbol : nullptr, joinComplete4331, child.joinComplete4331},
        {first ? nullptr : D::Functions[1][D::JoinComplete].symbol, joinComplete43224, child.joinComplete43224},
        {first ? D::Functions[0][D::BSSInit].symbol : nullptr, bssInit4331, child.bssInit4331},
        {first ? nullptr : D::Functions[1][D::BSSInit].symbol, bssInit43224, child.bssInit43224},
        {first ? D::Functions[0][D::ClearBSSID].symbol : nullptr, clearBSSID4331, child.clearBSSID},
        {first ? D::Functions[0][D::CfgMfree].symbol : nullptr, cfgMfree4331, child.cfgMfree},
        {first ? D::Functions[0][D::CfgFree].symbol : nullptr, cfgFree4331, child.cfgFree},
        {first ? nullptr : D::Functions[1][D::Down].symbol, down43224, child.down},
        {D::Functions[admission.child][D::Detach].symbol, first ? detach4331 : detach43224, child.detach},
        {D::Functions[admission.child][D::WlcStop].symbol, first ? wlcStop4331 : wlcStop43224, child.wlcStop},
        {D::Functions[admission.child][D::Worker].symbol, first ? worker4331 : worker43224, child.worker},
        {first ? D::Functions[0][D::CfgFind].symbol : nullptr, findCFG4331, child.findCFG},
        {D::Functions[admission.child][D::Disable].symbol, first ? disable4331 : disable43224, child.disable},
        {D::Functions[admission.child][D::SetDisassociate].symbol, first ? setter4331 : setter43224, child.setter}
    };
    for (size_t n = 0; n < sizeof(routes) / sizeof(routes[0]); ++n) {
        auto &route = routes[n];
        if (!route.symbol) continue;
        patcher.clearError();
        const bool routed = patcher.routeMultiple(admission.index, &route, 1,
                                                  admission.image.base, admission.image.size);
        const bool ok = routed && patcher.getError() == KernelPatcher::Error::NoError;
        patcher.clearError();
        if (!ok) return false;
    }
    if (!child.worker || !child.disable || !child.setter || !child.detach || !child.wlcStop || !child.builder ||
        (first ? !child.sender4331 : !child.sender43224) ||
        (first ? (!child.findCFG || !child.bssInit4331 || !child.clearBSSID || !child.cfgMfree || !child.cfgFree || !child.recvParser || !child.joinComplete4331)
               : (!child.bssInit43224 || !child.down || !child.joinComplete43224))) return false;
    __atomic_store_n(&child.active, 1U, __ATOMIC_RELEASE);
    return true;
}

int perform(LegacyBridge::Handler original, void *controller, void *interface,
            void *virtualInterface, LegacyBridge::Request *request, bool user64,
            uint32_t reason, uint32_t flush) {
    // The native SET22 entry converts the entire flush dword to bool before
    // the later FSM tests bit 0 of that normalized byte. The input is not a
    // flag mask: 2, 3 and values with only upper bits set also request a flush.
    if ((!reason && !flush) || !original || virtualInterface || !request ||
        request->type != 22 || (request->length != 8 && request->length != 12) ||
        (request->length == 8 && flush) || !user64) return EOPNOTSUPP;
    if (!__atomic_load_n(&configured, __ATOMIC_ACQUIRE) || !safeThread()) return EOPNOTSUPP;
    const Source source = api.classify(controller, interface);
    if (!ready(source)) return EOPNOTSUPP;
    bool enhanceRequested = false;
    if (reason) {
        bool enabled = true;
        if (!api.enhancedReasonConfiguration ||
            !api.enhancedReasonConfiguration(controller, &enabled))
            return EOPNOTSUPP;
        // Native leaveNetworkSync suppresses only the vendor-IE helper when
        // this gate is disabled. It still executes ordinary disassociation.
        // The independent flush request, if present, keeps its full checks.
        if (!enabled && !flush) return original(controller, interface, virtualInterface, request, user64);
        enhanceRequested = enabled;
    }
    CacheKernel::Lease lease;
    if (!lease.acquire(controller, interface, source)) return EOPNOTSUPP;
    constexpr size_t capacity = CacheKernel::MaximumPruneNodes;
    constexpr size_t bytes = sizeof(SelectiveCache::Entry) * capacity;
    auto *scratch = flush ? static_cast<SelectiveCache::Entry *>(api.allocate(bytes)) : nullptr;
    if (flush && !scratch) return ENOMEM;
    Scope scope;
    scope.thread = api.currentThread();
    scope.controller = controller; scope.interface = interface;
    scope.lease = &lease; scope.child = &children[childIndex(source)];
    scope.reason = reason; scope.enhanceRequested = enhanceRequested;
    {
        MemoryGuard guard;
        scope.memoryEpoch = scope.child->memory.snapshotEpoch();
    }
    int error = EBUSY;
    if (scope.thread && scope.memoryEpoch && addScope(scope)) {
        error = original(controller, interface, virtualInterface, request, user64);
        removeScope(scope);
        bool unchanged = false;
        {
            MemoryGuard guard;
            unchanged = scope.child->memory.readable(scope.memoryEpoch);
        }
        if (!error) {
            if (scope.failed) error = scope.failure ? scope.failure : EOPNOTSUPP;
            else if (scope.setterSeen && scope.idleCompleted &&
                     !scope.disableSeen && !scope.workerSeen) {
                // The original setter ran once and its proven idle branch
                // skipped command0x34. Preserve its local cleanup, perform no
                // reason-frame/cache action, and never infer this from zero
                // BSSID, a missing worker, or the upper handler's return alone.
                if (!unchanged || !lease.current()) error = ESTALE;
                else {
                    MemoryGuard guard;
                    IdleObservation finalState;
                    if (!readNativeIdle(scope, finalState) ||
                        finalState.wlc != scope.idle.wlc ||
                        finalState.cfg != scope.idle.cfg ||
                        finalState.association != scope.idle.association) error = ESTALE;
                }
                scope.idleCompleted = false;
            }
            else if (!scope.setterSeen || !scope.disableSeen || !scope.workerSeen ||
                     !scope.completion.consumeCompleted(scope.binding)) error = EOPNOTSUPP;
            else if (!unchanged || !lease.current()) error = ESTALE;
            else if (flush) {
                SelectiveCache::Result result {};
                error = pruneError(CacheKernel::prune(lease, scope.snapshot.network, scratch, capacity, &result));
            }
        }
    }
    if (scratch) {
        memset(scratch, 0, bytes);
        api.deallocate(scratch, bytes);
    }
    memset(&scope.snapshot, 0, sizeof(scope.snapshot));
    memset(&scope.binding, 0, sizeof(scope.binding));
    return error;
}
} }
