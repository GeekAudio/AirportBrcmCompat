// Bounded decoding and projection for legacy BSD SET request adapters.
// Routing and provider compatibility are validated separately in the legacy
// bridge; this helper only checks and copies the byte layout.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_BSD_SET_ADAPTER_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_BSD_SET_ADAPTER_HPP

#include <sys/errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi { namespace BSDSetAdapter {

constexpr size_t AuthNativeSize = 16;
constexpr size_t AuthLegacySize = 12;
constexpr size_t DisassociateReasonSize = 8;
constexpr size_t DisassociateFlushSize = 12;

struct DisassociateMetadata {
    uint32_t reason = 0;
    uint32_t flush = 0;
};

// Compare address ranges using integer differences, avoiding pointer ordering
// or pointer addition across unrelated objects. The helper only calls this
// with the fixed, small request sizes above.
inline bool rangesOverlap(const void *left, size_t leftLength,
                          const void *right, size_t rightLength) {
    const uintptr_t leftAddress = reinterpret_cast<uintptr_t>(left);
    const uintptr_t rightAddress = reinterpret_cast<uintptr_t>(right);
    // A range that wraps the address space is invalid for this operation.
    if ((leftLength && leftLength - 1 > UINTPTR_MAX - leftAddress) ||
        (rightLength && rightLength - 1 > UINTPTR_MAX - rightAddress))
        return true;
    if (leftAddress <= rightAddress)
        return rightAddress - leftAddress < leftLength;
    return leftAddress - rightAddress < rightLength;
}

// Decode an already owned copy. The first word is not a version discriminator:
// retained producers use both zero and an initialization sentinel, and the
// native consumer does not read it. Preserve the complete reason and flush
// words for policy validation. The native SET22 entry normalizes the complete
// flush dword to bool; the later FSM bit-0 check is on that normalized value,
// not on the original word. The eight-byte layout has no flush word. Unknown
// sizes must not be truncated.
inline int decodeDisassociate(const uint8_t *input, size_t inputLength,
                              DisassociateMetadata *output) {
    if (inputLength != DisassociateReasonSize && inputLength != DisassociateFlushSize)
        return EOPNOTSUPP;
    if (!input || !output || rangesOverlap(input, inputLength, output, sizeof(*output)))
        return EINVAL;
    DisassociateMetadata result {};
    memcpy(&result.reason, input + 4, sizeof(result.reason));
    if (inputLength == DisassociateFlushSize)
        memcpy(&result.flush, input + 8, sizeof(result.flush));
    *output = result;
    return 0;
}

// Sonoma's AUTH_TYPE request is {version, AUTH_LOWER, AUTH_UPPER,
// AUTH_UPPER_EXT}. The old provider understands only the first three words.
// Keep that prefix byte-for-byte; reject a nonzero extension rather than
// silently dropping authentication semantics. No enum interpretation or
// narrowing is applied to either auth word.
inline int projectAuthType(const uint8_t *input, size_t inputLength,
                           uint8_t *output, size_t outputCapacity) {
    if (!input || !output) return EINVAL;
    if (inputLength != AuthNativeSize) return EINVAL;
    if (outputCapacity < AuthLegacySize) return ENOBUFS;
    // Overlap is defined on bytes accessed: the full 16-byte source and the
    // 12-byte destination prefix written by this helper. Spare output capacity
    // beyond that prefix is not read or written.
    if (rangesOverlap(input, AuthNativeSize, output, AuthLegacySize))
        return EINVAL;

    uint32_t version = 0;
    uint32_t upperExtension = 0;
    memcpy(&version, input, sizeof(version));
    if (version != 1) return EINVAL;
    memcpy(&upperExtension, input + 12, sizeof(upperExtension));
    if (upperExtension != 0) return EOPNOTSUPP;

    // All rejection conditions precede the first output write.
    memcpy(output, input, AuthLegacySize);
    return 0;
}

} } // namespace LegacyWiFi::BSDSetAdapter

#endif
