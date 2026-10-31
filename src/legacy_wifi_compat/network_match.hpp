// Network identity predicate for the SET22 selective scan-cache operation.
// Inputs are owned, normalized identities, never native BSS object layouts.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_NETWORK_MATCH_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_NETWORK_MATCH_HPP

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/errno.h>

namespace LegacyWiFi {
namespace NetworkMatch {

constexpr size_t MaximumSSIDLength = 32;
enum class FILS : uint8_t { Unknown, Absent, Present };

struct Identity {
    uint8_t ssid[MaximumSSIDLength] {};
    uint8_t ssidLength = 0;
    uint16_t encryptionModes = 0;
    uint16_t apMode = 0;
    FILS fils = FILS::Unknown;
};

// The inspected BSS getter maps the two capability bits through {0,2,1,3}.
// A reference mode of 3 bypasses the candidate-mode equality check. No
// public enum label or unverified security-bit interpretation is assigned.
inline bool valid(const Identity &identity) {
    return identity.ssidLength <= MaximumSSIDLength && identity.apMode <= 3 &&
        static_cast<uint8_t>(identity.fils) <= static_cast<uint8_t>(FILS::Present);
}

// Corresponds to the retained native isOnNetwork predicate: candidate FILS
// exclusion, encryption-mask intersection, reference-mode policy, exact SSID.
// BSSID/channel/band are deliberately absent from this network identity.
// Errors leave the output unchanged so malformed input cannot become a
// successful deletion decision. Deriving identities and deleting provider
// nodes are separate operations; this helper performs neither.
inline int matches(const Identity *candidate, const Identity *reference,
                   bool *sameNetwork) {
    if (!candidate || !reference || !sameNetwork ||
        !valid(*candidate) || !valid(*reference)) return EINVAL;
    // The predicate reads only the candidate's FILS state. Missing source
    // metadata cannot be replaced by an assumed false flag; the reference's
    // state is irrelevant to this comparison and may remain unknown.
    if (candidate->fils == FILS::Unknown) return EOPNOTSUPP;
    const bool same = candidate->fils == FILS::Absent &&
        (candidate->encryptionModes & reference->encryptionModes) != 0 &&
        (reference->apMode == 3 || candidate->apMode == reference->apMode) &&
        candidate->ssidLength == reference->ssidLength &&
        memcmp(candidate->ssid, reference->ssid, candidate->ssidLength) == 0;
    *sameNetwork = same;
    return 0;
}

} // namespace NetworkMatch
} // namespace LegacyWiFi

#endif
