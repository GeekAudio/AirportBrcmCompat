// Portable private-station-address transaction policy. No platform operations.
// Never clears the private request, writes user payloads, or restores an address.
#ifndef SKYWALK_PRIVATE_MAC_TRANSACTION_HPP
#define SKYWALK_PRIVATE_MAC_TRANSACTION_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>

namespace PrivateMAC {
enum class Stage : uint32_t {
    None, Quarantined, Reentrant, InvalidAPI, PrivateRequest, AddressShape,
    Authorization, RegistryUnlocked, ControllerGate, Unassociated, PolicySource,
    SetFirmware, VerifyDriverCache, SetPrimaryBSD, VerifyPrimaryBSD,
    PublishCurrentIOMAC, VerifyCurrentIOMAC, ScopeCopy, AssociationResult
};
struct Result {
    int error;
    Stage stage;
    bool consistentPrivate;
    bool quarantined;
};
struct State {
    // One state per retained primary controller/interface generation. Caller
    // serializes access using the OLD controller gate, not the scope registry.
    bool quarantined=false, running=false, awaitingHandler=false, ready=false;
    Stage firstFailure=Stage::None;
    int firstError=0;
    uint8_t privateAddress[6] {};
};
using Check=int (*)(void *);
using AddressOperation=int (*)(void *,const uint8_t *);
struct API {
    void *context=nullptr;
    // Zero succeeds. The platform adapter supplies errors in the caller's
    // required domain; this engine never guesses errno from IOReturn values.
    Check authorization=nullptr;       // actual current kauth root credentials
    Check registryUnlocked=nullptr;    // this thread does not own scope registry lock
    Check controllerGate=nullptr;      // retained old controller gate is owned
    Check unassociated=nullptr;        // fail while associated/tearing down
    AddressOperation policySource=nullptr; // native private policy, never identity fallback
    AddressOperation setFirmware=nullptr;
    AddressOperation verifyDriverCache=nullptr; // cache consistency, NOT RF proof
    AddressOperation setPrimaryBSD=nullptr;
    AddressOperation verifyPrimaryBSD=nullptr;
    AddressOperation publishCurrentIOMAC=nullptr;
    AddressOperation verifyCurrentIOMAC=nullptr;
};
inline int blockError(const State &s) {
    return s.quarantined?EIO:(s.running||s.awaitingHandler?EBUSY:0);
}
inline bool blocked(const State &s) { return blockError(s)!=0; }
inline bool privateShape(const uint8_t *p) {
    return p && !(p[0]&1U) && (p[0]&2U); // locally administered unicast
}
inline Result fail(State &s,Stage stage,int error,bool mutated) {
    if (!error) error=EIO;
    if (mutated) {
        s.quarantined=true;s.ready=false;s.awaitingHandler=false;
        if (s.firstFailure==Stage::None) {s.firstFailure=stage;s.firstError=error;}
    }
    return {error,stage,false,s.quarantined};
}
inline bool completeAPI(const API &a) {
    return a.context && a.authorization && a.registryUnlocked && a.controllerGate &&
           a.unassociated && a.policySource && a.setFirmware && a.verifyDriverCache &&
           a.setPrimaryBSD && a.verifyPrimaryBSD && a.publishCurrentIOMAC && a.verifyCurrentIOMAC;
}
inline Result guards(API &a,State &s,bool mutated,bool requireUnassociated) {
    if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
    const struct {Stage stage;Check call;} checks[] = {
        {Stage::Authorization,a.authorization},{Stage::RegistryUnlocked,a.registryUnlocked},
        {Stage::ControllerGate,a.controllerGate}
    };
    for (const auto &check:checks) {
        const int error=check.call(a.context);
        if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
        if (error) return fail(s,check.stage,error,mutated);
    }
    if (requireUnassociated) {
        const int error=a.unassociated(a.context);
        if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
        if (error) return fail(s,Stage::Unassociated,error,mutated);
    }
    return {0,Stage::None,s.ready,s.quarantined};
}
struct Running {
    State &state;
    explicit Running(State &s):state(s) {state.running=true;}
    ~Running() {state.running=false;}
    Running(const Running &)=delete;
    Running &operator=(const Running &)=delete;
};
inline Result apply(API &a,State &s,const uint8_t *desired,bool privateRequested) {
    if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
    if (s.running || s.awaitingHandler) return {EBUSY,Stage::Reentrant,false,false};
    if (!completeAPI(a)) return fail(s,Stage::InvalidAPI,EINVAL,false);
    if (!privateRequested) return fail(s,Stage::PrivateRequest,EOPNOTSUPP,false);
    if (!privateShape(desired)) return fail(s,Stage::AddressShape,EINVAL,false);
    Running running(s);
    Result status=guards(a,s,false,true);
    if (status.error) return status;
    int error=a.policySource(a.context,desired);
    if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
    if (error) return fail(s,Stage::PolicySource,error,false);
    const struct {Stage stage;AddressOperation call;bool mayMutate;} steps[] = {
        {Stage::SetFirmware,a.setFirmware,true},
        {Stage::VerifyDriverCache,a.verifyDriverCache,false},
        {Stage::SetPrimaryBSD,a.setPrimaryBSD,true},
        {Stage::VerifyPrimaryBSD,a.verifyPrimaryBSD,false},
        {Stage::PublishCurrentIOMAC,a.publishCurrentIOMAC,true},
        {Stage::VerifyCurrentIOMAC,a.verifyCurrentIOMAC,false}
    };
    bool mutated=false;
    for (const auto &step:steps) {
        status=guards(a,s,mutated,true);
        if (status.error) return status;
        // A failing firmware setter may already have changed state/PMK. Any
        // mutating operation attempted makes all subsequent failures quarantine.
        mutated|=step.mayMutate;
        error=step.call(a.context,desired);
        if (error) return fail(s,step.stage,error,mutated);
        if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
    }
    memcpy(s.privateAddress,desired,6);s.ready=true;s.awaitingHandler=true;
    return {0,Stage::VerifyCurrentIOMAC,true,false};
}
inline Result scopeCopyFailed(State &s,int error=EIO) {
    // Invoke after releasing the registry lock. No backend/identity fallback.
    return fail(s,Stage::ScopeCopy,error,true);
}
inline Result associationReturned(API &a,State &s,int originalError,bool copied) {
    // Only called for an apply() which succeeded. The short ioctl scope is
    // already unlinked; no native/legacy payload pointer is retained here.
    if (s.quarantined) return {originalError?originalError:EIO,Stage::Quarantined,false,true};
    if (!s.ready || !s.awaitingHandler || !copied) return scopeCopyFailed(s);
    if (s.running) return fail(s,Stage::Reentrant,EBUSY,true);
    if (!completeAPI(a)) return fail(s,Stage::InvalidAPI,EINVAL,true);
    Running running(s);
    s.awaitingHandler=false;
    Result status=guards(a,s,true,false); // joining can now be in progress
    if (status.error) return status;
    const struct {Stage stage;AddressOperation call;} checks[] = {
        {Stage::VerifyDriverCache,a.verifyDriverCache},
        {Stage::VerifyPrimaryBSD,a.verifyPrimaryBSD},
        {Stage::VerifyCurrentIOMAC,a.verifyCurrentIOMAC}
    };
    for (const auto &check:checks) {
        status=guards(a,s,true,false);
        if (status.error) return status;
        const int error=check.call(a.context,s.privateAddress);
        if (error) return fail(s,check.stage,error,true);
        if (s.quarantined) return {EIO,Stage::Quarantined,false,true};
    }
    // An association error never restores an old address or PMK/connection.
    // Address cache consistency does NOT establish link/RF/DHCP success.
    return {originalError,Stage::AssociationResult,true,false};
}
} // namespace PrivateMAC
#endif
