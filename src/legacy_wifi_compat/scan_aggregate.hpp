// Bounded owned snapshots for emulating SET86 result semantics with repeated
// El Capitan SET11 scans. Results are appended in scan/result order; no
// unverified BSSID or channel offsets are used for deduplication.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_AGGREGATE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_AGGREGATE_HPP

#include "scan_bridge.hpp"

namespace LegacyWiFi {
namespace ScanAggregate {

constexpr size_t MaximumResults = 512;
constexpr size_t RecordSize = ScanCompat::OldSize;
constexpr size_t StorageSize = MaximumResults * RecordSize;

inline int snapshotKernelResult(const uint8_t *kernelHeader, size_t headerSize,
                                uint8_t *fixedOldResult, size_t outputSize) {
    if (!kernelHeader || headerSize != ScanBridge::KernelHeaderSize ||
        !fixedOldResult || outputSize != RecordSize) return EINVAL;
    const size_t length = ScanBridge::read16(kernelHeader + ScanBridge::IELengthOffset);
    const uint64_t address = ScanBridge::read64(
        kernelHeader + ScanBridge::KernelIEPointerOffset);
    if (ScanBridge::read32(kernelHeader) != 1) return EINVAL;
    if (length > ScanBridge::MaximumIEBytes) return EOVERFLOW;
    if (length && (!address || address > static_cast<uint64_t>(UINTPTR_MAX) - length))
        return EFAULT;
    memset(fixedOldResult, 0, RecordSize);
    memcpy(fixedOldResult, kernelHeader, ScanCompat::IEOffset);
    if (length)
        memcpy(fixedOldResult + ScanCompat::IEOffset,
               reinterpret_cast<const void *>(static_cast<uintptr_t>(address)), length);
    return 0;
}

struct API {
    void (*deallocate)(void *, size_t) = nullptr;
};

struct Detached {
    uint8_t *storage = nullptr;
    API api {};
};

// One completed SET86 operation is keyed by the interface's retained session
// and its retained request-owner PID. The pool is allocated at admission and
// retained through EOF, so a GET11 after EOF never falls through to the
// manager's final child-scan node.
class Store {
public:
    Store() = default;
    Store(const Store &) = delete;
    Store &operator=(const Store &) = delete;

    bool begin(int ownerPID) {
        if (active_ || ownerPID <= 0) return false;
        api_ = {};
        storage_ = nullptr;
        ownerPID_ = ownerPID;
        count_ = 0;
        cursor_ = 0;
        leaseActive_ = false;
        error_ = 0;
        complete_ = false;
        active_ = true;
        return true;
    }

    void setStorage(uint8_t *storage, const API &api) {
        if (!active_ || storage_ || !storage || !api.deallocate) return;
        storage_ = storage;
        api_ = api;
    }

    Detached clear() {
        Detached detached {storage_, api_};
        storage_ = nullptr;
        ownerPID_ = 0;
        count_ = cursor_ = 0;
        leaseActive_ = false;
        error_ = 0;
        complete_ = active_ = false;
        api_ = {};
        return detached;
    }

    static void destroy(Detached detached) {
        if (!detached.storage) return;
        memset(detached.storage, 0, StorageSize);
        if (detached.api.deallocate)
            detached.api.deallocate(detached.storage, StorageSize);
    }

    bool active() const { return active_ && ownerPID_ > 0; }
    bool complete() const { return active() && complete_; }
    bool leased() const { return active() && leaseActive_; }
    int error() const { return active() ? error_ : 0; }
    int ownerPID() const { return active() ? ownerPID_ : 0; }
    size_t count() const { return active() ? count_ : 0; }
    size_t cursor() const { return active() ? cursor_ : 0; }

    int append(const uint8_t *fixedOldResult, size_t size) {
        if (!active() || !storage_ || complete_ || !fixedOldResult || size != RecordSize)
            return EINVAL;
        if (count_ == MaximumResults) return EOVERFLOW;
        memcpy(storage_ + count_ * RecordSize, fixedOldResult, RecordSize);
        ++count_;
        return 0;
    }

    void finish(int error = 0) {
        if (!active() || complete_) return;
        error_ = error;
        if (error_ || !storage_) {
            // A partial union must never look like a successful scan. Storage
            // is cleared later outside the spin lock that protects this state.
            if (!error_) error_ = ENOMEM;
            count_ = cursor_ = 0;
            leaseActive_ = false;
        }
        complete_ = true;
    }

    // `managed` distinguishes an unrelated PID (which should use the native
    // handler) from pending/error/EOF states (which must be consumed here).
    int peek(int callerPID, uint8_t *fixedOldResult, size_t size,
             bool *managed, uint64_t *token) {
        if (!managed || !token) return EINVAL;
        *managed = false;
        *token = 0;
        if (!active() || callerPID != ownerPID_) return 0;
        *managed = true;
        if (!complete_) return EBUSY;
        if (error_) return error_;
        if (!storage_ || !fixedOldResult || size != RecordSize) return ENOMEM;
        if (cursor_ >= count_) return EIO; // Persistent EOF; never fallback.
        if (leaseActive_) return EBUSY;
        memcpy(fixedOldResult, storage_ + cursor_ * RecordSize, RecordSize);
        leaseToken_ = nextToken();
        leaseActive_ = true;
        *token = leaseToken_;
        return 0;
    }

    bool commit(int callerPID, uint64_t token, bool copiedOut) {
        if (!active() || callerPID != ownerPID_ || !leaseActive_ ||
            !token || token != leaseToken_) return false;
        if (copiedOut) ++cursor_;
        leaseActive_ = false;
        return true;
    }

private:
    static uint64_t nextToken() {
        // Tokens are unique across Store instances as well as clear/begin
        // lifecycles, so a delayed GET11 commit cannot match a new interface
        // session that happens to reuse the same address and PID.
        static uint64_t counter = 0;
        uint64_t value = __atomic_add_fetch(&counter, 1U, __ATOMIC_RELAXED);
        if (!value)
            value = __atomic_add_fetch(&counter, 1U, __ATOMIC_RELAXED);
        return value;
    }

    API api_ {};
    uint8_t *storage_ = nullptr;
    int ownerPID_ = 0;
    size_t count_ = 0;
    size_t cursor_ = 0;
    uint64_t leaseToken_ = 0;
    int error_ = 0;
    bool complete_ = false;
    bool active_ = false;
    bool leaseActive_ = false;
};

} // namespace ScanAggregate
} // namespace LegacyWiFi

#endif
