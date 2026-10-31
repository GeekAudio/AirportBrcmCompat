// Single-executable core entry points. Linking these does not register hooks,
// fabricate a user client, subscribe events or make privateMAC/AWDL available.
#include "compat_core.hpp"

namespace AirportBrcmCore {
PrivateMAC::NativeResult parsePrivateRequest(const uint8_t *p,size_t n,PrivateMAC::NativeRequest &out) {
    return PrivateMAC::parseNative(p,n,out);
}
PrivateMAC::Result applyPrivateAddress(PrivateMAC::API &api,PrivateMAC::State &state,
                                     const uint8_t *address,bool requested) {
    return PrivateMAC::apply(api,state,address,requested);
}
PrivateMAC::Result finishPrivateAssociation(PrivateMAC::API &api,PrivateMAC::State &state,
                                           int originalError,bool copied) {
    return PrivateMAC::associationReturned(api,state,originalError,copied);
}
PrivateMAC::StateGate::Result checkStationState(const PrivateMAC::StateGate::Access &a,
                                               uintptr_t controller,uintptr_t primary) {
    return PrivateMAC::StateGate::check(a,controller,primary);
}
int admitPrimaryAssociation(PrivateMAC::Admission &admission,const PrivateMAC::Binding &binding,
                            uintptr_t owner,PrivateMAC::AdmissionLease &lease) {
    return admission.enter(binding,owner,lease);
}
int quarantinePrimaryAssociation(PrivateMAC::Admission &admission,const PrivateMAC::AdmissionLease &lease,
                                 uintptr_t owner,uint32_t reason) {
    return admission.poison(lease,owner,reason);
}
int releasePrimaryAssociation(PrivateMAC::Admission &admission,const PrivateMAC::AdmissionLease &lease,
                              uintptr_t owner) {
    return admission.finish(lease,owner);
}
} // namespace AirportBrcmCore
