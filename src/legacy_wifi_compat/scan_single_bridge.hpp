// Strict Apple80211 SET10 schema projection to the fixed El Cap single-scan
// request or a canonical SET86 payload for the verified multi-scan routes.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_SINGLE_BRIDGE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_SINGLE_BRIDGE_HPP

#include "provider_contract.hpp"
#include "scan_multiple_bridge.hpp"
#include <sys/errno.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi {
namespace ScanSingleBridge {

constexpr size_t ElCapSize = ProviderContract::SingleRequestMaxSize;
constexpr size_t VersionOffset = 0x00;
constexpr size_t APModeOffset = 0x04;
constexpr size_t BSSIDOffset = 0x08;
constexpr size_t SSIDLengthOffset = 0x10;
constexpr size_t SSIDBytesOffset = 0x14;
constexpr size_t SSIDCapacity = 32;
constexpr size_t ScanTypeOffset = 0x34;
constexpr size_t PHYModeOffset = 0x38;
constexpr size_t DwellTimeOffset = 0x3c;
constexpr size_t RestTimeOffset = 0x40;
constexpr size_t ChannelCountOffset = 0x44;
constexpr size_t ChannelsOffset = 0x48;
constexpr size_t ChannelStride = 12;
constexpr size_t MaxElCapChannels = 128;
constexpr size_t MaxNativeSSIDList = 9;
constexpr size_t NativeSSIDStride = 0x38;
constexpr size_t NativeSSIDTypeOffset = 0x00;
constexpr size_t NativeSSIDLengthOffset = 0x04;
constexpr size_t NativeSSIDBytesOffset = 0x08;
constexpr size_t NativeSSIDBytesCapacity = 32;

enum class Profile : uint8_t {
    Monterey12,
    Ventura13,
    Sonoma14,
    Sequoia15Tahoe26
};

struct NativeLayout {
    Profile profile = Profile::Monterey12;
    size_t size = 0;
    size_t channelCapacity = 0;
    size_t channelsEnd = 0;
    size_t flagsOffset = 0;
    size_t ssidCountOffset = 0;
    size_t ssidArrayOffset = 0;
    size_t ssidArrayEnd = 0;
};

struct Result {
    int error = 0;
    size_t field = 0;
};

constexpr size_t Monterey12Size = 0x888;
constexpr size_t Ventura13Size = 0x1550;
constexpr size_t Sonoma14Size = 0x1590;
constexpr size_t Sequoia15Tahoe26Size = 0x1598;
constexpr size_t Monterey12ChannelEnd = 0x648;
constexpr size_t ModernChannelEnd = 0x1308;
constexpr size_t Monterey12Flags = 0x648;
constexpr size_t ModernFlags = 0x1308;
constexpr size_t Monterey12SSIDCount = 0x654;
constexpr size_t ModernSSIDCount = 0x1314;
constexpr size_t Monterey12SSIDArray = 0x658;
constexpr size_t ModernSSIDArray = 0x1318;

static_assert(ChannelsOffset + 128 * ChannelStride == Monterey12ChannelEnd,
              "12.7.2 SET10 has a 128-channel table");
static_assert(ChannelsOffset + 400 * ChannelStride == ModernChannelEnd,
              "13.7.8/14/15/26 SET10 has a 400-channel table");
static_assert(Monterey12SSIDArray + MaxNativeSSIDList * NativeSSIDStride == 0x850,
              "12.7.2 SET10 SSID extension boundary");
static_assert(ModernSSIDArray + MaxNativeSSIDList * NativeSSIDStride == 0x1510,
              "13.7.8/14/15/26 SET10 SSID extension boundary");
static_assert(ElCapSize == 0x954,
              "El Cap ScanManager fixed request-copy size");

inline bool nativeLayoutForSize(size_t size, NativeLayout &layout) {
    if (size == Monterey12Size) {
        layout = {Profile::Monterey12, size, 128, Monterey12ChannelEnd,
                  Monterey12Flags, Monterey12SSIDCount, Monterey12SSIDArray, 0x850};
        return true;
    }
    if (size == Ventura13Size) {
        layout = {Profile::Ventura13, size, 400, ModernChannelEnd,
                  ModernFlags, ModernSSIDCount, ModernSSIDArray, 0x1510};
        return true;
    }
    if (size == Sonoma14Size) {
        layout = {Profile::Sonoma14, size, 400, ModernChannelEnd,
                  ModernFlags, ModernSSIDCount, ModernSSIDArray, 0x1510};
        return true;
    }
    if (size == Sequoia15Tahoe26Size) {
        layout = {Profile::Sequoia15Tahoe26, size, 400, ModernChannelEnd,
                  ModernFlags, ModernSSIDCount, ModernSSIDArray, 0x1510};
        return true;
    }
    return false;
}

inline bool overlaps(const void *left, size_t leftSize,
                     const void *right, size_t rightSize) {
    const uintptr_t a = reinterpret_cast<uintptr_t>(left);
    const uintptr_t b = reinterpret_cast<uintptr_t>(right);
    return a <= b ? b - a < leftSize : a - b < rightSize;
}

inline bool allZero(const uint8_t *bytes, size_t begin, size_t end,
                    size_t *firstNonzero = nullptr) {
    for (size_t i = begin; i < end; ++i) {
        if (bytes[i]) {
            if (firstNonzero) *firstNonzero = i;
            return false;
        }
    }
    return true;
}

inline uint32_t read32(const uint8_t *bytes, size_t offset) {
    return ScanCompat::read32(bytes + offset);
}

inline void write32(uint8_t *bytes, size_t offset, uint32_t value) {
    memcpy(bytes + offset, &value, sizeof(value));
}

inline bool sameLayout(const NativeLayout &a, const NativeLayout &b) {
    return a.profile == b.profile && a.size == b.size &&
        a.channelCapacity == b.channelCapacity && a.channelsEnd == b.channelsEnd &&
        a.flagsOffset == b.flagsOffset && a.ssidCountOffset == b.ssidCountOffset &&
        a.ssidArrayOffset == b.ssidArrayOffset && a.ssidArrayEnd == b.ssidArrayEnd;
}

// The sampled native SET10 producers zero the entire request before filling
// this common apple80211_scan_data prefix. They then append the optional scan
// flags qword and a 9-entry SSID list. The channel table and SSID extension
// move together between 12 and 13+, while the prefix offsets remain fixed.
// Only zero-valued flags and post-list tail fields are admitted here; nonzero
// extension flags include features that the El Cap request cannot represent.
inline Result validateNativeShape(const uint8_t *native, size_t nativeSize,
                                 const NativeLayout *expectedLayout = nullptr) {
    NativeLayout layout{};
    if (!native || !nativeLayoutForSize(nativeSize, layout)) return {EINVAL, 0};
    if (expectedLayout && !sameLayout(layout, *expectedLayout)) return {EINVAL, 0};

    if (read32(native, VersionOffset) != 1) return {EINVAL, VersionOffset};
    const uint32_t apMode = read32(native, APModeOffset);
    if (apMode < 1 || apMode > 3) return {EINVAL, APModeOffset};
    const uint32_t ssidLength = read32(native, SSIDLengthOffset);
    if (ssidLength > SSIDCapacity) return {EINVAL, SSIDLengthOffset};
    if (!allZero(native, BSSIDOffset + 6, SSIDLengthOffset))
        return {EINVAL, BSSIDOffset + 6};
    if (!allZero(native, SSIDBytesOffset + ssidLength, ScanTypeOffset))
        return {EINVAL, SSIDBytesOffset + ssidLength};

    const uint32_t scanType = read32(native, ScanTypeOffset);
    if (scanType < 1 || scanType > 3) return {EINVAL, ScanTypeOffset};
    if (!allZero(native, DwellTimeOffset + sizeof(uint16_t), RestTimeOffset))
        return {EINVAL, DwellTimeOffset + sizeof(uint16_t)};

    const uint32_t channelCount = read32(native, ChannelCountOffset);
    if (channelCount > layout.channelCapacity) return {EINVAL, ChannelCountOffset};
    const size_t usedChannels = ChannelsOffset + size_t(channelCount) * ChannelStride;
    size_t bad = 0;
    if (!allZero(native, usedChannels, layout.channelsEnd, &bad))
        return {EINVAL, bad};

    if (!allZero(native, layout.flagsOffset, layout.flagsOffset + sizeof(uint64_t), &bad))
        return {EOPNOTSUPP, layout.flagsOffset};
    if (!allZero(native, layout.flagsOffset + sizeof(uint64_t),
                 layout.ssidCountOffset, &bad))
        return {EOPNOTSUPP, bad};

    const uint32_t ssidListCount = read32(native, layout.ssidCountOffset);
    if (ssidListCount > MaxNativeSSIDList)
        return {EINVAL, layout.ssidCountOffset};
    const size_t listEnd = layout.ssidArrayOffset +
        size_t(ssidListCount) * NativeSSIDStride;
    for (uint32_t i = 0; i < ssidListCount; ++i) {
        const size_t record = layout.ssidArrayOffset + size_t(i) * NativeSSIDStride;
        const uint32_t type = read32(native, record + NativeSSIDTypeOffset);
        const uint32_t length = read32(native, record + NativeSSIDLengthOffset);
        if (type != 1) return {EINVAL, record + NativeSSIDTypeOffset};
        if (length > NativeSSIDBytesCapacity)
            return {EINVAL, record + NativeSSIDLengthOffset};
        if (!allZero(native, record + NativeSSIDBytesOffset + length,
                     record + NativeSSIDStride))
            return {EINVAL, record + NativeSSIDBytesOffset + length};
    }
    if (!allZero(native, listEnd, layout.ssidArrayEnd, &bad))
        return {EINVAL, bad};
    if (!allZero(native, layout.ssidArrayEnd, layout.size, &bad))
        return {EOPNOTSUPP, bad};

    if (ssidListCount && ssidLength) return {EOPNOTSUPP, SSIDLengthOffset};
    return {0, 0};
}

inline Result convertToElCap(const uint8_t *native, size_t nativeSize,
                             uint8_t *elCap, size_t elCapSize) {
    NativeLayout layout{};
    if (!native || !elCap || elCapSize != ElCapSize ||
        !nativeLayoutForSize(nativeSize, layout) ||
        overlaps(native, nativeSize, elCap, elCapSize)) return {EINVAL, 0};
    const Result shape = validateNativeShape(native, nativeSize, &layout);
    if (shape.error) return shape;

    const uint32_t channelCount = read32(native, ChannelCountOffset);
    if (channelCount > MaxElCapChannels) return {EOPNOTSUPP, ChannelCountOffset};
    const uint32_t ssidListCount = read32(native, layout.ssidCountOffset);
    if (ssidListCount > 1) return {EOPNOTSUPP, layout.ssidCountOffset};

    memset(elCap, 0, elCapSize);
    memcpy(elCap, native, ChannelsOffset);
    if (ssidListCount == 1) {
        const size_t record = layout.ssidArrayOffset;
        const uint32_t length = read32(native, record + NativeSSIDLengthOffset);
        write32(elCap, SSIDLengthOffset, length);
        if (length)
            memcpy(elCap + SSIDBytesOffset,
                   native + record + NativeSSIDBytesOffset, length);
    }
    if (channelCount)
        memcpy(elCap + ChannelsOffset, native + ChannelsOffset,
               size_t(channelCount) * ChannelStride);
    return {0, 0};
}

inline Result normalizeToScanMultiple(const uint8_t *native, size_t nativeSize,
                                      uint8_t *multiple, size_t multipleSize) {
    NativeLayout layout{};
    if (!native || !multiple || multipleSize != ScanMultipleBridge::NativeSize ||
        !nativeLayoutForSize(nativeSize, layout) ||
        overlaps(native, nativeSize, multiple, multipleSize)) return {EINVAL, 0};
    const Result shape = validateNativeShape(native, nativeSize, &layout);
    if (shape.error) return shape;

    const uint32_t directSSIDLength = read32(native, SSIDLengthOffset);
    const uint32_t ssidListCount = read32(native, layout.ssidCountOffset);
    const uint32_t channelCount = read32(native, ChannelCountOffset);
    const uint32_t bssidPresent = allZero(native, BSSIDOffset, BSSIDOffset + 6) ? 0 : 1;
    const uint32_t outputSSIDCount = ssidListCount ? ssidListCount :
        (directSSIDLength ? 1 : 0);

    memset(multiple, 0, multipleSize);
    write32(multiple, 0, 1);
    write32(multiple, 4, read32(native, APModeOffset));
    write32(multiple, ScanMultipleBridge::NativeSSIDCount, outputSSIDCount);
    for (uint32_t i = 0; i < outputSSIDCount; ++i) {
        const size_t record = ScanMultipleBridge::NativeSSIDArray +
            size_t(i) * ScanMultipleBridge::SSIDStride;
        const uint8_t *ssidBytes = nullptr;
        uint32_t ssidLength = 0;
        if (ssidListCount) {
            const size_t inputRecord = layout.ssidArrayOffset + size_t(i) * NativeSSIDStride;
            ssidLength = read32(native, inputRecord + NativeSSIDLengthOffset);
            ssidBytes = native + inputRecord + NativeSSIDBytesOffset;
        } else {
            ssidLength = directSSIDLength;
            ssidBytes = native + SSIDBytesOffset;
        }
        write32(multiple, record, 1);
        write32(multiple, record + ScanMultipleBridge::SSIDLengthOffset, ssidLength);
        if (ssidLength)
            memcpy(multiple + record + ScanMultipleBridge::SSIDBytesOffset,
                   ssidBytes, ssidLength);
    }

    write32(multiple, ScanMultipleBridge::NativeBSSIDCount, bssidPresent);
    if (bssidPresent)
        memcpy(multiple + ScanMultipleBridge::NativeBSSIDArray,
               native + BSSIDOffset, 6);
    write32(multiple, ScanMultipleBridge::NativeScanType, read32(native, ScanTypeOffset));
    write32(multiple, ScanMultipleBridge::NativePhyMode, read32(native, PHYModeOffset));
    write32(multiple, ScanMultipleBridge::NativeDwellTime,
            ScanCompat::read16(native + DwellTimeOffset));
    write32(multiple, ScanMultipleBridge::NativeRestTime, read32(native, RestTimeOffset));
    write32(multiple, ScanMultipleBridge::NativeChannelCount, channelCount);
    if (channelCount)
        memcpy(multiple + ScanMultipleBridge::NativeChannels,
               native + ChannelsOffset, size_t(channelCount) * ChannelStride);
    return {0, 0};
}

} // namespace ScanSingleBridge
} // namespace LegacyWiFi

#endif
