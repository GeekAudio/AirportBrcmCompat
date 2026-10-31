// Decode the Network Assurance bit from a bounded IEEE 802.11 IE sequence.
// The result describes only the bytes supplied by the caller; absence does
// not prove that a reused Beacon object had its bit cleared.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_NETWORK_ASSURANCE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_NETWORK_ASSURANCE_HPP

#include <stddef.h>
#include <stdint.h>
#include <sys/errno.h>

namespace LegacyWiFi {
namespace NetworkAssurance {

enum class State : uint8_t { Unknown, Disabled, Enabled };

constexpr size_t MaximumIETailBytes = 1024;
constexpr uint8_t VendorSpecificElementID = 221;
constexpr uint8_t CCXSubtype = 0x0b;
constexpr uint8_t NetworkAssuranceMask = 0x80;
constexpr uint8_t CCXOUI[3] = {0x00, 0x40, 0x96};

// `ies` is an IE tail, not a Beacon/Probe Response body. The native Tahoe
// parser dispatches on vendor-specific EID 221 + OUI 00:40:96, requires at
// least five vendor-body bytes, then checks body[3] == 0x0b and body[4]&0x80.
// Every complete IE is walked. The last valid matching IE wins. No match is
// Unknown because this snapshot cannot establish freshness of a reused BSS.
// Any malformed IE makes the whole result unusable; output is unchanged.
inline int parse(const uint8_t *ies, size_t length, State *output) {
    if (!output || (length && !ies)) return EINVAL;
    if (length > MaximumIETailBytes) return EOVERFLOW;

    State result = State::Unknown;
    size_t cursor = 0;
    while (cursor < length) {
        const size_t remaining = length - cursor;
        if (remaining < 2) return EINVAL;

        const uint8_t elementID = ies[cursor];
        const size_t bodyLength = ies[cursor + 1];
        if (bodyLength > remaining - 2) return EINVAL;

        if (elementID == VendorSpecificElementID && bodyLength >= 5) {
            const uint8_t *body = ies + cursor + 2;
            if (body[0] == CCXOUI[0] && body[1] == CCXOUI[1] &&
                body[2] == CCXOUI[2] && body[3] == CCXSubtype) {
                result = (body[4] & NetworkAssuranceMask) ?
                    State::Enabled : State::Disabled;
            }
        }
        cursor += 2 + bodyLength;
    }

    *output = result;
    return 0;
}

} // namespace NetworkAssurance
} // namespace LegacyWiFi

#endif
