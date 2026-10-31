// Decode owned fixed scan snapshots from the two pinned El Capitan children.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_NETWORK_IDENTITY_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_NETWORK_IDENTITY_HPP

#include "network_match.hpp"
#include "scan_bridge.hpp"

namespace LegacyWiFi {
namespace NetworkIdentity {

// This is a source contract, not a PCI-device or OS-version selector. The
// runtime caller must already have verified the corresponding injected child
// and provider images before assigning one of these values.
enum class Source : uint8_t { Unknown, Pinned4331, Pinned43224 };

constexpr size_t CapabilityOffset = 0x1a;
constexpr size_t SSIDLengthOffset = 0x60;
constexpr size_t SSIDOffset = 0x61;
constexpr size_t FlagsOffset = 0x88;

// Both pinned children zero the result allocation and leave byte+0x88 zero.
// The provider's cache copy and the owned inline snapshot preserve that byte.
// This proves FILS absence for these producers; a general legacy result does
// not have the same provenance merely because its field happens to be zero.
// On every failure the output identity is unchanged.
inline int decode(Source source, const uint8_t *snapshot, size_t size,
                  NetworkMatch::Identity *output) {
    if (source != Source::Pinned4331 && source != Source::Pinned43224)
        return EOPNOTSUPP;
    if (!snapshot || !output || size != ScanBridge::FixedLegacyResultSize)
        return EINVAL;
    if (ScanBridge::read32(snapshot) != 1 ||
        snapshot[SSIDLengthOffset] > NetworkMatch::MaximumSSIDLength)
        return EINVAL;
    if (snapshot[FlagsOffset] != 0) return EOPNOTSUPP;
    const size_t ieLength = ScanBridge::read16(snapshot + ScanBridge::IELengthOffset);
    if (ieLength > ScanBridge::MaximumIEBytes) return EOVERFLOW;

    uint16_t encryptionModes = 0;
    size_t cursor = 0;
    while (cursor < ieLength) {
        if (ieLength - cursor < 2) return EINVAL;
        const uint8_t *ie = snapshot + ScanCompat::IEOffset + cursor;
        const size_t length = ie[1];
        if (length > ieLength - cursor - 2) return EINVAL;
        if (length) {
            if (ie[0] == 48) {
                // Native classification sets this bit even when the RSN
                // suite parser cannot decode the nonempty body.
                encryptionModes |= 0x08;
            } else if (ie[0] == 0x44) {
                // Preserve the observed numeric classification; no unproven
                // public security-mode name is assigned to this bit.
                encryptionModes |= 0x10;
            } else if (ie[0] == 221 && length >= 4 &&
                       ie[2] == 0x00 && ie[3] == 0x50 &&
                       ie[4] == 0xf2 && ie[5] == 0x01) {
                encryptionModes |= 0x04;
            }
        }
        cursor += length + 2;
    }

    const uint16_t capability = ScanBridge::read16(snapshot + CapabilityOffset);
    if (!(encryptionModes & 0x1c))
        encryptionModes = capability & 0x10 ? 2 : 1;
    static const uint16_t capabilityToAPMode[4] = {0, 2, 1, 3};
    NetworkMatch::Identity identity {};
    identity.ssidLength = snapshot[SSIDLengthOffset];
    memcpy(identity.ssid, snapshot + SSIDOffset, identity.ssidLength);
    identity.encryptionModes = encryptionModes;
    identity.apMode = capabilityToAPMode[capability & 3];
    identity.fils = NetworkMatch::FILS::Absent;
    *output = identity;
    return 0;
}

} // namespace NetworkIdentity
} // namespace LegacyWiFi

#endif
