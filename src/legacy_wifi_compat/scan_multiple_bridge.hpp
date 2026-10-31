// Strict native-v25 SET86 to the ElCap 0x908 scan-multiple request.
// This codec only establishes byte-layout conversion; the sampled ElCap
// AppleAirPortBrcm43224 driver has no setSCAN_REQ_MULTIPLE implementation.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_MULTIPLE_BRIDGE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_MULTIPLE_BRIDGE_HPP

#include "../scan_kernel/scan_multiple_compat.hpp"
#include <errno.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi {
namespace ScanMultipleBridge {

constexpr size_t NativeSize=ScanMultipleCompat::NativeSize;
constexpr size_t ElCapSize=0x908;
constexpr size_t NativeSSIDCount=0x08;
constexpr size_t NativeSSIDArray=0x0c;
constexpr size_t SSIDStride=0x28;
constexpr size_t SSIDLengthOffset=0x04;
constexpr size_t SSIDBytesOffset=0x08;
constexpr size_t MaxNativeSSIDs=10;
constexpr size_t MaxBSSIDs=16;
constexpr size_t MaxElCapChannels=128;
constexpr size_t ChannelStride=12;
constexpr size_t NativeBSSIDCount=0x19c;
constexpr size_t NativeBSSIDArray=0x1a0;
constexpr size_t NativeScanType=0x200;
constexpr size_t NativePhyMode=0x204;
constexpr size_t NativeDwellTime=0x208;
constexpr size_t NativeRestTime=0x20c;
constexpr size_t NativeChannelCount=0x210;
constexpr size_t NativeChannels=0x214;
constexpr size_t NativeChannelsEnd=0x14d4;
constexpr size_t NativeUnmappedTail=NativeChannelsEnd;
constexpr size_t ElCapBSSIDCount=0x28c;
constexpr size_t ElCapBSSIDArray=0x290;
constexpr size_t ElCapScanType=0x2f0;
constexpr size_t ElCapPhyMode=0x2f4;
constexpr size_t ElCapDwellTime=0x2f8;
constexpr size_t ElCapRestTime=0x2fc;
constexpr size_t ElCapChannelCount=0x300;
constexpr size_t ElCapChannels=0x304;
constexpr size_t ElCapChannelEnd=ElCapChannels+MaxElCapChannels*ChannelStride;
constexpr size_t ElCapUnknownTail=ElCapChannelEnd;

static_assert(NativeChannels+400*ChannelStride==NativeChannelsEnd,
              "Pinned native SET86 channel table");
static_assert(ElCapChannelEnd==0x904 && ElCapUnknownTail+4==ElCapSize,
              "Pinned ElCap 128-channel buffer and trailing word");

struct Result { int error=0; size_t field=0; };

inline bool overlaps(const void *left,size_t leftSize,const void *right,size_t rightSize) {
    const uintptr_t a=reinterpret_cast<uintptr_t>(left);
    const uintptr_t b=reinterpret_cast<uintptr_t>(right);
    return a<=b ? b-a<leftSize : a-b<rightSize;
}

inline bool allZero(const uint8_t *bytes,size_t begin,size_t end,size_t *firstNonzero=nullptr) {
    for (size_t i=begin;i<end;i++) if (bytes[i]) {
        if (firstNonzero) *firstNonzero=i;
        return false;
    }
    return true;
}

// ElCap v2.0.1's setScanRequestMultiple/ScanManager/4331 path establishes:
//   version/apmode/ssidCount at 0/4/8; 16 SSID records at +0x0c, stride 40;
//   BSSID count/list at +0x28c/+0x290, max 16;
//   scanType/phy/dwell16/rest/channelCount at +0x2f0..+0x300;
//   128 12-byte apple80211_channel records at +0x304.
// The modern request has ten SSID slots and 400 channels. We move only the
// used records and fields. The native trailing 20 bytes are not mapped by the
// ElCap consumer, so this converter admits only their all-zero form.
inline Result convertToElCap(const uint8_t *native,size_t nativeSize,
                             uint8_t *elCap,size_t elCapSize) {
    if (!native || !elCap || nativeSize!=NativeSize || elCapSize!=ElCapSize ||
        overlaps(native,nativeSize,elCap,elCapSize)) return {EINVAL,0};
    if (ScanCompat::read32(native)!=1) return {EINVAL,0};

    const uint32_t ssidCount=ScanCompat::read32(native+NativeSSIDCount);
    if (ssidCount>MaxNativeSSIDs) return {EINVAL,NativeSSIDCount};
    const uint32_t bssidCount=ScanCompat::read32(native+NativeBSSIDCount);
    if (bssidCount>MaxBSSIDs) return {EINVAL,NativeBSSIDCount};
    const uint32_t channelCount=ScanCompat::read32(native+NativeChannelCount);
    if (channelCount>400) return {EINVAL,NativeChannelCount};
    if (channelCount>MaxElCapChannels) return {EOPNOTSUPP,NativeChannelCount};

    const uint32_t apMode=ScanCompat::read32(native+4);
    const uint32_t scanType=ScanCompat::read32(native+NativeScanType);
    if (apMode<1 || apMode>3) return {EINVAL,4};
    if (scanType<1 || scanType>3) return {EINVAL,NativeScanType};
    if (ScanCompat::read32(native+NativeDwellTime)>UINT16_MAX)
        return {EOPNOTSUPP,NativeDwellTime};

    for (uint32_t i=0;i<ssidCount;i++) {
        const size_t record=NativeSSIDArray+size_t(i)*SSIDStride;
        if (ScanCompat::read32(native+record+SSIDLengthOffset)>32)
            return {EINVAL,record+SSIDLengthOffset};
    }
    size_t unmapped=0;
    if (!allZero(native,NativeUnmappedTail,NativeSize,&unmapped))
        return {EOPNOTSUPP,unmapped};

    uint8_t projected[ElCapSize] {};
    memcpy(projected,native,12); // version, ap mode, SSID count
    if (ssidCount)
        memcpy(projected+NativeSSIDArray,native+NativeSSIDArray,size_t(ssidCount)*SSIDStride);
    memcpy(projected+ElCapBSSIDCount,native+NativeBSSIDCount,4);
    if (bssidCount)
        memcpy(projected+ElCapBSSIDArray,native+NativeBSSIDArray,size_t(bssidCount)*6);
    memcpy(projected+ElCapScanType,native+NativeScanType,4);
    memcpy(projected+ElCapPhyMode,native+NativePhyMode,4);
    ScanCompat::write16(projected+ElCapDwellTime,
                        static_cast<uint16_t>(ScanCompat::read32(native+NativeDwellTime)));
    memcpy(projected+ElCapRestTime,native+NativeRestTime,4);
    memcpy(projected+ElCapChannelCount,native+NativeChannelCount,4);
    if (channelCount)
        memcpy(projected+ElCapChannels,native+NativeChannels,size_t(channelCount)*ChannelStride);
    memcpy(elCap,projected,sizeof(projected));
    memset(projected,0,sizeof(projected));
    return {0,0};
}

} // namespace ScanMultipleBridge
} // namespace LegacyWiFi

#endif
