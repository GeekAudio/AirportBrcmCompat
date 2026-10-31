// Shared declarations, not hook registration or proof of completed features.
#ifndef AIRPORT_BRCM_COMPAT_CORE_HPP
#define AIRPORT_BRCM_COMPAT_CORE_HPP
#include "../private_mac_compat/transaction.hpp"
#include "../private_mac_compat/state_gate.hpp"
#include "../private_mac_compat/admission.hpp"
#include "../private_mac_compat/native_request.hpp"
namespace AirportBrcmCore {
PrivateMAC::NativeResult parsePrivateRequest(const uint8_t *,size_t,PrivateMAC::NativeRequest &);
PrivateMAC::Result applyPrivateAddress(PrivateMAC::API &,PrivateMAC::State &,const uint8_t *,bool);
PrivateMAC::Result finishPrivateAssociation(PrivateMAC::API &,PrivateMAC::State &,int,bool);
PrivateMAC::StateGate::Result checkStationState(const PrivateMAC::StateGate::Access &,uintptr_t,uintptr_t);
int admitPrimaryAssociation(PrivateMAC::Admission &,const PrivateMAC::Binding &,uintptr_t,PrivateMAC::AdmissionLease &);
int quarantinePrimaryAssociation(PrivateMAC::Admission &,const PrivateMAC::AdmissionLease &,uintptr_t,uint32_t);
int releasePrimaryAssociation(PrivateMAC::Admission &,const PrivateMAC::AdmissionLease &,uintptr_t);
}
#endif
