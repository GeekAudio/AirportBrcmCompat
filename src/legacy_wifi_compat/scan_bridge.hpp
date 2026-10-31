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
constexpr size_t MaximumNativeRequestSize = ScanCompat::NativeSize;
constexpr size_t FixedLegacyResultSize = ScanCompat::OldSize;
constexpr size_t MaximumIEBytes = ScanCompat::OldIECapacity;
inline size_t resultIECapacity(size_t size) {
    return size==ScanCompat::OldSize?MaximumIEBytes:ScanCompat::resultIECapacity(size);
}

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
    const size_t nativeIECapacity = resultIECapacity(nativeSize);
    if (!native || !kernelHeader || !nativeIECapacity ||
        headerSize != KernelHeaderSize) return EINVAL;
    const size_t actual = read16(kernelHeader + IELengthOffset);
    if (actual > MaximumIEBytes) return EOVERFLOW;
    if (ieSnapshotSize != actual || (actual && !ieSnapshot)) return EINVAL;

    uint8_t fixed[FixedLegacyResultSize] {};
    memcpy(fixed, kernelHeader, ScanCompat::IEOffset);
    write16(fixed + IELengthOffset, static_cast<uint16_t>(actual));
    if (actual) memcpy(fixed + ScanCompat::IEOffset, ieSnapshot, actual);
    const int error = nativeSize==ScanCompat::OldSize?
        ScanCompat::convertFixedResult(native,nativeSize,fixed,sizeof(fixed)):
        ScanCompat::convert(native, nativeSize, fixed, sizeof(fixed));
    memset(fixed, 0, sizeof(fixed));
    return error;
}

// Convert an already-owned 0x48c inline legacy result. Runtime GET11
// aggregation uses this path after peeking a bounded snapshot; cursor commit
// remains the caller's responsibility and must follow successful copyOut.
inline int convertFixedSnapshot(uint8_t *native, size_t nativeSize,
                                const uint8_t *fixedLegacy,
                                size_t legacySize) {
    if (!native || !fixedLegacy || legacySize != FixedLegacyResultSize)
        return EINVAL;
    if (nativeSize == ScanCompat::OldSize)
        return ScanCompat::convertFixedResult(native, nativeSize,
                                              fixedLegacy, legacySize);
    return ScanCompat::convert(native, nativeSize, fixedLegacy, legacySize);
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
    bool (*primaryInterface)(void *controller, void *interface,
                             const char requestName[16]) = nullptr;
};

struct Buffer {
    API &api;
    size_t size;
    uint8_t *bytes;
    explicit Buffer(API &value, size_t length)
        : api(value), size(length), bytes(static_cast<uint8_t *>(value.allocate(length))) {}
    ~Buffer() {
        if (bytes) {
            memset(bytes, 0, size);
            api.deallocate(bytes, size);
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
    return request && request->type == 11 &&
        resultIECapacity(request->length) != 0;
}

// Copy one owned aggregate record without consuming the manager's cursor.
// The caller commits its lease only after this complete operation succeeds.
inline int copyFixedSnapshot(API &api,void *controller,void *interface,
                             ScanCompat::Request *request,const uint8_t *fixed,
                             size_t fixedSize) {
    if (!targetsNativeGet11(request) || !controller || !interface || !fixed ||
        fixedSize!=FixedLegacyResultSize || !request->userData ||
        request->value || request->padding) return EINVAL;
    const size_t nativeSize=request->length;
    Buffer native(api,nativeSize);
    if (!native.bytes) return ENOMEM;
    int error=api.copyIn(controller,request->userData,native.bytes,nativeSize);
    if (error) return error;
    if (read32(native.bytes)!=1 ||
        read16(native.bytes+IELengthOffset)>resultIECapacity(nativeSize)) return EINVAL;
    error=nativeSize==ScanCompat::OldSize?
        ScanCompat::convertFixedResult(native.bytes,nativeSize,fixed,fixedSize):
        ScanCompat::convert(native.bytes,nativeSize,fixed,fixedSize);
    if (error) return error;
    if (!api.primaryInterface ||
        !api.primaryInterface(controller,interface,request->interfaceName)) return ESTALE;
    return api.copyOut(controller,native.bytes,request->userData,nativeSize);
}

inline int handle(API &api, void *controller, void *interface, void *virtualInterface,
                  ScanCompat::Request *request, bool user64) {
    if (!targetsNativeGet11(request) || !user64 || !interface)
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

    const size_t nativeSize = request->length;
    const size_t nativeIECapacity = resultIECapacity(nativeSize);
    Buffer native(api, nativeSize);
    if (!native.bytes) return ENOMEM;
    error = api.copyIn(controller, request->userData, native.bytes, nativeSize);
    if (error) return error;
    if (read32(native.bytes) != 1 || read16(native.bytes + IELengthOffset) > nativeIECapacity)
        return EINVAL;
    error = convertResult(native.bytes, nativeSize, snapshot.header,
                          sizeof(snapshot.header), snapshot.ies, ieLength);
    if (error) return error;
    if (api.primaryInterface &&
        !api.primaryInterface(controller, interface, request->interfaceName)) return ESTALE;
    return api.copyOut(controller, native.bytes, request->userData, nativeSize);
}

} // namespace ScanBridge
} // namespace LegacyWiFi

#endif
