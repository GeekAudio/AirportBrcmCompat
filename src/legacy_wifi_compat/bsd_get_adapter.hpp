// Small, bounded adapters for legacy BSD GET replies whose modern caller
// changed the returned buffer envelope. These helpers are byte-layout only;
// request routing and provider/callsite proof stay in legacy_bridge/runtime.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_BSD_GET_ADAPTER_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_BSD_GET_ADAPTER_HPP

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi { namespace BSDGetAdapter {

constexpr uint32_t GetStatePointerSize = 8;
constexpr size_t GetStateValueOffset = 4;
constexpr size_t GetStateValueSize = 4;

constexpr uint32_t GetAPIEListLegacyCapacity = 0x400;
constexpr size_t GetAPIEListHeaderSize = 8;
constexpr size_t GetAPIEListLengthOffset = 4;
constexpr size_t GetAPIEListBytesOffset = 8;
constexpr uint32_t GetAPIEListNativeMinimum =
    GetAPIEListLegacyCapacity + GetAPIEListHeaderSize;
constexpr uint32_t GetAPIEListNativeExtended = 0x808;
constexpr size_t GetAPIEListNativeMaximum =
    GetAPIEListLegacyCapacity + GetAPIEListHeaderSize;

inline bool stateUsesPointerEnvelope(uint32_t length, uint64_t userData) {
    return length == GetStatePointerSize && userData != 0;
}

// The sampled 13/14 and 15/26 callers reserve 0x408 and 0x808 respectively.
// The older 12.x donor requests only 0x400 bytes, so its raw IE list stays on
// the original provider path. Unknown capacities do not guess a schema.
inline bool ieListUsesHeaderEnvelope(uint32_t length, uint64_t userData) {
    return (length == GetAPIEListNativeMinimum ||
            length == GetAPIEListNativeExtended) && userData != 0;
}

inline bool addUserAddress(uint64_t base, size_t offset, size_t length,
                           uint64_t &result) {
    if (!base || !length || offset > UINT64_MAX - base) return false;
    result = base + static_cast<uint64_t>(offset);
    return length - 1 <= UINT64_MAX - result;
}

inline int encodeState(int32_t state, uint8_t output[GetStateValueSize]) {
    if (!output) return EINVAL;
    // Preserve the provider's full 32-bit scalar without narrowing or adding
    // an enum assumption the child-driver identity guard does not prove.
    memcpy(output, &state, GetStateValueSize);
    return 0;
}

inline int encodeIEList(const uint8_t *raw, size_t rawLength,
                        uint8_t *output, size_t outputCapacity,
                        size_t *encodedLength) {
    if (!output || !encodedLength || (rawLength && !raw)) return EINVAL;
    if (rawLength > GetAPIEListLegacyCapacity) return EOVERFLOW;
    const size_t required = GetAPIEListHeaderSize + rawLength;
    if (outputCapacity < required) return ENOBUFS;

    memset(output, 0, required);
    const uint32_t version = 1;
    const uint16_t wireLength = static_cast<uint16_t>(rawLength);
    memcpy(output, &version, sizeof(version));
    memcpy(output + GetAPIEListLengthOffset, &wireLength, sizeof(wireLength));
    if (rawLength)
        memcpy(output + GetAPIEListBytesOffset, raw, rawLength);
    *encodedLength = required;
    return 0;
}

} } // namespace LegacyWiFi::BSDGetAdapter

#endif
