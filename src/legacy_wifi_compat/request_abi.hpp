// Bounded decoder for the BSD apple80211req envelope used by the
// OS X 10.11 / IO80211ElCap path. This does not describe any ioctl payload.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_REQUEST_ABI_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_REQUEST_ABI_HPP

#include <stdint.h>
#include <stddef.h>
#include <string.h>

namespace LegacyWiFi {
namespace RequestABI {

constexpr size_t InterfaceNameOffset = 0x00;
constexpr size_t TypeOffset = 0x10;
constexpr size_t ValueOffset = 0x14;
constexpr size_t LengthOffset = 0x18;
constexpr size_t Data32Offset = 0x1c;
constexpr size_t Data64Offset = 0x20;
constexpr size_t User32Size = 0x20;
constexpr size_t User64Size = 0x28;
constexpr size_t KernelSize = 0x28;

struct View {
    char interfaceName[16] {};
    int32_t type = 0;
    int32_t value = 0;
    uint32_t length = 0;
    uint64_t data = 0;
    bool user64 = false;
};

inline int32_t readI32(const uint8_t *p) {
    int32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}
inline uint32_t readU32(const uint8_t *p) {
    uint32_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}
inline uint64_t readU64(const uint8_t *p) {
    uint64_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}
inline void writeU32(uint8_t *p, uint32_t value) { memcpy(p, &value, sizeof(value)); }
inline void writeU64(uint8_t *p, uint64_t value) { memcpy(p, &value, sizeof(value)); }

// ElCap's UserlandToKernel converter reads the same field positions and
// widens a 32-bit userspace pointer into the x86_64 kernel request. It passes
// proc_is64bit separately to handlers; the canonical kernel envelope is 40
// bytes in either case. The 64-bit user's padding at +0x1c is not interpreted.
inline bool decode(const void *bytes, size_t size, bool user64, View &out) {
    const size_t required = user64 ? User64Size : User32Size;
    if (!bytes || size != required) return false;
    const auto *raw = static_cast<const uint8_t *>(bytes);
    View decoded {};
    memcpy(decoded.interfaceName, raw + InterfaceNameOffset, sizeof(decoded.interfaceName));
    decoded.type = readI32(raw + TypeOffset);
    decoded.value = readI32(raw + ValueOffset);
    decoded.length = readU32(raw + LengthOffset);
    decoded.data = user64 ? readU64(raw + Data64Offset) : readU32(raw + Data32Offset);
    decoded.user64 = user64;
    out = decoded;
    return true;
}

// Build the fixed 40-byte x86_64 kernel apple80211req prefix consumed by
// IO80211ElCap handlers. The user-width flag remains an explicit side input.
inline void encodeKernel(const View &request, uint8_t out[KernelSize]) {
    memset(out, 0, KernelSize);
    memcpy(out + InterfaceNameOffset, request.interfaceName, sizeof(request.interfaceName));
    memcpy(out + TypeOffset, &request.type, sizeof(request.type));
    memcpy(out + ValueOffset, &request.value, sizeof(request.value));
    writeU32(out + LengthOffset, request.length);
    writeU64(out + Data64Offset, request.data);
}

} // namespace RequestABI
} // namespace LegacyWiFi

#endif
