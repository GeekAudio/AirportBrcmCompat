// State transitions shared by the kernel registry and its offline race test.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_EVENT_BINDING_STATE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_EVENT_BINDING_STATE_HPP

#include <stdint.h>

namespace LegacyWiFi {
namespace EventContracts {

enum class BindingState : uint8_t {
    Empty,
    Creating,
    Active,
    AbortRequested,
    Retired,
};

inline BindingState bindingTerminationRequested(BindingState state) {
    if (state == BindingState::Creating) return BindingState::AbortRequested;
    if (state == BindingState::Active) return BindingState::Retired;
    return state;
}

inline BindingState bindingCreationFinished(BindingState state, bool success) {
    if (state == BindingState::Creating && success) return BindingState::Active;
    if (state == BindingState::Creating || state == BindingState::AbortRequested)
        return BindingState::Retired;
    return state;
}

inline bool bindingSlotAvailable(BindingState state) {
    return state == BindingState::Empty;
}

} // namespace EventContracts
} // namespace LegacyWiFi

#endif
