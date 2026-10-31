// Normalize producer-specific SET20 layouts before the shared strict validator.
#ifndef SKYWALK_ASSOCIATION_PROFILES_HPP
#define SKYWALK_ASSOCIATION_PROFILES_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>

namespace AssociationProfiles {
constexpr size_t Sonoma14Size=856;
constexpr size_t Sequoia15Size=900;
constexpr size_t SharedNativeSize=908;
constexpr size_t LegacyAssociationSize=548;
constexpr size_t LegacyPrefixSize=508;

struct ProfileResult { int error; uint32_t field; };

inline bool overlap(const void *a,size_t an,const void *b,size_t bn) {
    const auto x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    return x<=y ? y-x<an : x-y<bn;
}

inline uint16_t read16(const uint8_t *p) {
    return static_cast<uint16_t>(p[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(p[1])<<8);
}
inline uint32_t read32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1])<<8) |
           (static_cast<uint32_t>(p[2])<<16) |
           (static_cast<uint32_t>(p[3])<<24);
}

// Sonoma 14's Associate2 producer builds an 856-byte SET20 with the same
// 16-bit mode/auth header and byte offsets as the old 548-byte consumer through
// allowed-auths at 504. Preserve that prefix exactly; do not widen, narrow,
// default or otherwise reinterpret its authentication fields. The old driver
// receives a zeroed 40-byte tail because Sonoma's later scope/selection fields
// have no lossless representation there.
//
// This admits only open and WPA2 carriers whose semantics are understood by
// the old Brcm path. Scope is rejected at the producer's old flag byte 464 bit
// 0x40, and all extensions 508..855 are rejected unless zero. Sonoma's
// producer contains no PRIVATE_MAC_ADDRESS property contract, so bit 0x08 at
// 464 is neither interpreted nor stripped; the same prefix byte is retained.
inline ProfileResult convertSonoma14(const uint8_t *source,size_t sourceSize,
                                      uint8_t *legacy,size_t legacySize) {
    if (!source || !legacy || sourceSize!=Sonoma14Size ||
        legacySize!=LegacyAssociationSize ||
        overlap(source,sourceSize,legacy,legacySize)) return {EINVAL,0};

    if (read32(source)!=1) return {EINVAL,0};
    if (read16(source+4)!=2) return {EOPNOTSUPP,4};
    const uint16_t lower=read16(source+6),upper=read16(source+8);
    if (lower>1) return {EOPNOTSUPP,6};
    if (upper!=0 && upper!=8) return {EOPNOTSUPP,8};
    const uint32_t ssid=read32(source+12);
    if (!ssid || ssid>32) return {EINVAL,12};

    const uint32_t keyVersion=read32(source+56),key=read32(source+60);
    const uint32_t cipher=read32(source+64),pmk=read32(source+468);
    if (keyVersion>1) return {EOPNOTSUPP,56};
    if (key>64) return {EINVAL,60};
    if (pmk>32) return {EINVAL,468};
    if (read32(source+136)>8) return {EINVAL,136};
    if (read32(source+156)>16) return {EINVAL,156};
    if (read32(source+176)>16) return {EINVAL,176};
    if (read16(source+204)>257) return {EINVAL,204};

    if (source[464]&0x40U) return {EOPNOTSUPP,464}; // COLOCATED_NETWORK_SCOPE_ID.
    const uint32_t allowed=read32(source+504);
    if (!upper) {
        if (cipher || key || pmk || allowed) return {EOPNOTSUPP,64};
        // Version1 is the only empty nested-key marker. No hidden key, RSN or
        // PMK bytes may turn an open request into a silent security downgrade.
        for (size_t j=60;j<463;j++) if (source[j]) return {EOPNOTSUPP,static_cast<uint32_t>(j)};
        for (size_t j=468;j<504;j++) if (source[j]) return {EOPNOTSUPP,static_cast<uint32_t>(j)};
    } else {
        const bool psk=(cipher==6 && key==32 && (pmk==0 || pmk==32)) ||
                       (cipher==10 && key>=1 && key<=64 && pmk==32);
        if (!psk) return {EOPNOTSUPP,64};
        if (allowed!=0 && allowed!=4 && allowed!=0x40000004U) return {EOPNOTSUPP,504};
    }
    for (size_t j=LegacyPrefixSize;j<Sonoma14Size;j++)
        if (source[j]) return {EOPNOTSUPP,static_cast<uint32_t>(j)};

    memset(legacy,0,LegacyAssociationSize);
    memcpy(legacy,source,LegacyPrefixSize);
    return {0,0};
}

// Sequoia 15's Apple80211Associate2 emits 900 bytes and zero-initializes the
// final byte. Its producer has no ASSOC_6G_ENABLE field. Tahoe's 908-byte
// schema assigns that same offset (899) the value 1/off or 2/unspecified.
// Convert only the observed zero-reserved Sequoia shape: preserve bytes 0..898,
// synthesize 2 solely in the private normalized copy to mean "unspecified",
// and zero the eight Tahoe-only appended bytes. This is not a native Sequoia
// field or proof of 6 GHz policy. The shared validator still checks every
// preserved extension and retains Tahoe's strict byte-899 rule.
inline ProfileResult normalizeSequoia15(const uint8_t *source,size_t sourceSize,
                                        uint8_t *normalized,size_t normalizedSize) {
    if (!source || !normalized || sourceSize!=Sequoia15Size ||
        normalizedSize!=SharedNativeSize ||
        overlap(source,sourceSize,normalized,normalizedSize)) return {EINVAL,0};
    if (source[899]!=0) return {EOPNOTSUPP,899};

    memset(normalized,0,SharedNativeSize);
    memcpy(normalized,source,899);
    normalized[899]=2;
    return {0,0};
}
} // namespace AssociationProfiles

#endif
