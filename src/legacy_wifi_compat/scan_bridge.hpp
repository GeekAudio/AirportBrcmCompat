// GET11 adapter for the pre-12 IO80211ElCap scan-result ABI.
// The source result is variable-length IE data behind a kernel pointer; the
// current native request carries a fixed inline IE array.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_BRIDGE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_BRIDGE_HPP

#include "../scan_kernel/scan_compat.hpp"
#include "request_abi.hpp"

namespace LegacyWiFi {
namespace ScanBridge {

// Verified from IO80211ElCap's getScanResult and
// IO80211ScanManager::getScanResult call sites: the kernel result header is
// copied as 0x98 bytes, IE length is at +0x8a, and the x86_64 IE pointer is at
// +0x90. User request lengths are 0x98 (64-bit) or 0x90 (32-bit), but this
// adapter consumes the manager's x86_64 kernel result, never that user header.
constexpr size_t KernelHeaderSize = 0x98;
constexpr size_t KernelIEPointerOffset = 0x90;
constexpr size_t IELengthOffset = 0x8a;
constexpr size_t NativeRequestSize = ScanCompat::NativeSize;
constexpr size_t FixedLegacyResultSize = ScanCompat::OldSize;
constexpr size_t MaximumIEBytes = ScanCompat::OldIECapacity;

using ScanCompat::read16;
using ScanCompat::read32;
using ScanCompat::write16;

inline uint64_t read64(const void *p) {
    uint64_t value;
    memcpy(&value, p, sizeof(value));
    return value;
}

// Materialize the old pointer-based result into the fixed old layout expected
// by the already-audited Ventura-to-native converter. `ieSnapshot` must be a
// synchronous snapshot of the bytes referenced by the kernel result header;
// this pure function never dereferences the embedded pointer.
inline int convertResult(uint8_t *native, size_t nativeSize,
                         const uint8_t *kernelHeader, size_t headerSize,
                         const uint8_t *ieSnapshot, size_t ieSnapshotSize) {
    if (!native || !kernelHeader || nativeSize != NativeRequestSize ||
        headerSize != KernelHeaderSize) return EINVAL;
    const size_t actual = read16(kernelHeader + IELengthOffset);
    if (actual > MaximumIEBytes) return EOVERFLOW;
    if (ieSnapshotSize != actual || (actual && !ieSnapshot)) return EINVAL;

    uint8_t fixed[FixedLegacyResultSize] {};
    memcpy(fixed, kernelHeader, ScanCompat::IEOffset);
    write16(fixed + IELengthOffset, static_cast<uint16_t>(actual));
    if (actual) memcpy(fixed + ScanCompat::IEOffset, ieSnapshot, actual);
    const int error = ScanCompat::convert(native, nativeSize, fixed, sizeof(fixed));
    memset(fixed, 0, sizeof(fixed));
    return error;
}

// This signature matches the ElCap static getScanResult handler:
// (controller, interface, virtual interface, apple80211req, user64).
using Original = int (*)(void *, void *, void *, ScanCompat::Request *, bool);
using CopyIn = int (*)(void *, uint64_t, void *, size_t);
using CopyOut = int (*)(void *, const void *, uint64_t, size_t);
using GetResult = int (*)(void *, const uint8_t **);

struct API {
    Original original = nullptr;
    void *(*allocate)(size_t) = nullptr;
    void (*deallocate)(void *, size_t) = nullptr;
    CopyIn copyIn = nullptr;
    CopyOut copyOut = nullptr;
    void *(*scanManager)(void *interface) = nullptr;
    GetResult getResult = nullptr;
};

struct Buffer {
    API &api;
    uint8_t *bytes;
    explicit Buffer(API &value)
        : api(value), bytes(static_cast<uint8_t *>(value.allocate(NativeRequestSize))) {}
    ~Buffer() {
        if (bytes) {
            memset(bytes, 0, NativeRequestSize);
            api.deallocate(bytes, NativeRequestSize);
        }
    }
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
};

struct KernelSnapshot {
    uint8_t header[KernelHeaderSize] {};
    uint8_t ies[MaximumIEBytes] {};
    KernelSnapshot() = default;
    ~KernelSnapshot() {
        memset(header, 0, sizeof(header));
        memset(ies, 0, sizeof(ies));
    }
    KernelSnapshot(const KernelSnapshot &) = delete;
    KernelSnapshot &operator=(const KernelSnapshot &) = delete;
};

inline bool targetsNativeGet11(const ScanCompat::Request *request) {
    return request && request->type == 11 && request->length == NativeRequestSize;
}

inline int handle(API &api, void *controller, void *interface, void *virtualInterface,
                  ScanCompat::Request *request, bool user64) {
    if (!targetsNativeGet11(request) || !interface)
        return api.original(controller, interface, virtualInterface, request, user64);
    if (!controller || !request->userData) return EINVAL;

    // Match IO80211ElCap's side-effect order: the handler gets the pending
    // result before it copyIn's the userspace output envelope. Snapshot the
    // manager-owned result first, so a userspace copy fault does not leave a
    // result pending when the original handler would already have consumed it.
    void *manager = api.scanManager(interface);
    if (!manager) return ENXIO;
    const uint8_t *result = nullptr;
    int error = api.getResult(manager, &result);
    if (error) return error;
    if (!result) return EIO;

    KernelSnapshot snapshot;
    memcpy(snapshot.header, result, sizeof(snapshot.header));
    const size_t ieLength = read16(snapshot.header + IELengthOffset);
    if (ieLength > sizeof(snapshot.ies)) return EOVERFLOW;
    const uint64_t ieAddress = read64(snapshot.header + KernelIEPointerOffset);
    if (ieLength && !ieAddress) {
        return EFAULT;
    }
    if (ieLength)
        memcpy(snapshot.ies, reinterpret_cast<const void *>(static_cast<uintptr_t>(ieAddress)), ieLength);

    Buffer native(api);
    if (!native.bytes) return ENOMEM;
    error = api.copyIn(controller, request->userData, native.bytes, NativeRequestSize);
    if (error) return error;
    if (read32(native.bytes) != 1 || read16(native.bytes + IELengthOffset) > ScanCompat::NativeIECapacity)
        return EINVAL;
    error = convertResult(native.bytes, NativeRequestSize, snapshot.header,
                          sizeof(snapshot.header), snapshot.ies, ieLength);
    if (error) return error;
    return api.copyOut(controller, native.bytes, request->userData, NativeRequestSize);
}

} // namespace ScanBridge
} // namespace LegacyWiFi

#endif
