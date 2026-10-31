// Bounded SET86 -> ElCap SET10 sequence support for drivers that expose only
// setSCAN_REQ. This header contains no IOKit calls: the owner supplies a
// workloop-gated scheduler, the audited ScanManager::startScan call, and an
// event-router publisher that bypasses the event-suppression detour.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_SEQUENCE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_SEQUENCE_HPP

#include "scan_multiple_bridge.hpp"

namespace LegacyWiFi {
namespace ScanSequence {

// ScanManager::startScan's fixed El Cap node-copy reads 0x954 bytes from
// apple80211_scan_data regardless of the caller's schema length. Every job
// therefore owns the entire buffer; the projected 128 channel records end at
// 0x648 and the remaining bytes stay zero.
constexpr size_t SingleScanSize = 0x954;
constexpr uint32_t ScanDoneEvent = 10;
constexpr uint32_t ScanManagerDoneEvent = 15;

constexpr size_t SingleVersion = 0x00;
constexpr size_t SingleAPMode = 0x04;
constexpr size_t SingleBSSID = 0x08;
constexpr size_t SingleSSIDLength = 0x10;
constexpr size_t SingleSSID = 0x14;
constexpr size_t SingleScanType = 0x34;
constexpr size_t SinglePhyMode = 0x38;
constexpr size_t SingleDwellTime = 0x3c;
constexpr size_t SingleRestTime = 0x40;
constexpr size_t SingleChannelCount = 0x44;
constexpr size_t SingleChannels = 0x48;
constexpr size_t SingleChannelCapacity = 128;
constexpr size_t MaxChannelChunks =
    (ScanMultipleBridge::MaxNativeChannels + SingleChannelCapacity - 1) /
    SingleChannelCapacity;
constexpr size_t MaxJobs = ScanMultipleBridge::MaxNativeSSIDs * MaxChannelChunks;

struct Result { int error = 0; size_t field = 0; };
struct Lock {
    void *value = nullptr;
    void (*enter)(void *) = nullptr;
    void (*leave)(void *) = nullptr;
};

inline void write32(void *pointer, uint32_t value) {
    memcpy(pointer, &value, sizeof(value));
}

inline bool overlaps(const void *left, size_t leftSize,
                     const void *right, size_t rightSize) {
    const uintptr_t a = reinterpret_cast<uintptr_t>(left);
    const uintptr_t b = reinterpret_cast<uintptr_t>(right);
    return a <= b ? b - a < leftSize : a - b < rightSize;
}

inline void clearPlan(uint8_t *jobs) {
    if (jobs) memset(jobs, 0, MaxJobs * SingleScanSize);
}

// ElCap's apple80211_scan_data fields and the 43224 setSCAN_REQ reads are
// fixed by the audited 10.11 binaries. Active/passive requests are split by
// non-empty SSID, BSSID filter, and channel chunk. Each old single-scan request
// has space for 128 channel records; the native 13/25 profiles can contain 400.
// Since the 43224 driver accepts one BSSID filter per scan_data request, a
// native BSSID list is split into one child scan per distinct address. The
// product stays within MaxJobs; larger requests are rejected before mutation.
// Type 3 uses the stock ScanManager::fastScanMultiple path and is not admitted.
inline Result build43224Plan(const uint8_t *native, size_t nativeSize,
                             uint8_t *jobs, size_t jobsSize,
                             uint32_t *jobCount) {
    if (!native || !jobs || !jobCount ||
        jobsSize < MaxJobs * SingleScanSize ||
        overlaps(native, nativeSize, jobs, MaxJobs * SingleScanSize))
        return {EINVAL, 0};

    const auto valid = ScanMultipleBridge::validateNativeShape(native, nativeSize);
    if (valid.error) return {valid.error, valid.field};

    const uint32_t bssidCount = ScanCompat::read32(native + ScanMultipleBridge::NativeBSSIDCount);
    const uint32_t scanType = ScanCompat::read32(native + ScanMultipleBridge::NativeScanType);
    if (scanType == 3) return {EOPNOTSUPP, ScanMultipleBridge::NativeScanType};

    uint8_t selectedBSSIDs[ScanMultipleBridge::MaxBSSIDs] {};
    uint32_t selectedBSSIDCount = 0;
    for (uint32_t i = 0; i < bssidCount; ++i) {
        const uint8_t *bssid = native + ScanMultipleBridge::NativeBSSIDArray + size_t(i) * 6;
        static const uint8_t zeroBSSID[6] {};
        if (memcmp(bssid, zeroBSSID, sizeof(zeroBSSID)) == 0)
            return {EOPNOTSUPP, ScanMultipleBridge::NativeBSSIDArray + size_t(i) * 6};
        bool duplicate = false;
        for (uint32_t j = 0; j < selectedBSSIDCount; ++j) {
            const uint8_t *prior = native + ScanMultipleBridge::NativeBSSIDArray +
                size_t(selectedBSSIDs[j]) * 6;
            if (memcmp(prior, bssid, 6) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) selectedBSSIDs[selectedBSSIDCount++] = static_cast<uint8_t>(i);
    }
    if (!selectedBSSIDCount) selectedBSSIDs[selectedBSSIDCount++] = 0xff;

    const uint32_t ssidCount = ScanCompat::read32(native + ScanMultipleBridge::NativeSSIDCount);
    const uint32_t channelCount = ScanCompat::read32(native + ScanMultipleBridge::NativeChannelCount);
    const uint32_t apMode = ScanCompat::read32(native + 4);
    const uint32_t phyMode = ScanCompat::read32(native + ScanMultipleBridge::NativePhyMode);
    const uint32_t dwellTime = ScanCompat::read32(native + ScanMultipleBridge::NativeDwellTime);
    const uint32_t restTime = ScanCompat::read32(native + ScanMultipleBridge::NativeRestTime);

    uint8_t selected[ScanMultipleBridge::MaxNativeSSIDs] {};
    uint32_t selectedCount = 0;
    for (uint32_t i = 0; i < ssidCount; ++i) {
        const size_t record = ScanMultipleBridge::NativeSSIDArray + size_t(i) *
            ScanMultipleBridge::SSIDStride;
        const uint32_t length = ScanCompat::read32(native + record +
                                                   ScanMultipleBridge::SSIDLengthOffset);
        if (!length) continue; // The audited driver skips empty SSID records.
        bool duplicate = false;
        for (uint32_t j = 0; j < selectedCount; ++j) {
            const size_t prior = ScanMultipleBridge::NativeSSIDArray + size_t(selected[j]) *
                ScanMultipleBridge::SSIDStride;
            if (ScanCompat::read32(native + prior + ScanMultipleBridge::SSIDLengthOffset) == length &&
                memcmp(native + prior + ScanMultipleBridge::SSIDBytesOffset,
                       native + record + ScanMultipleBridge::SSIDBytesOffset, length) == 0) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) selected[selectedCount++] = static_cast<uint8_t>(i);
    }
    if (!selectedCount) selected[selectedCount++] = 0xff; // wildcard/broadcast scan

    const uint32_t chunkCount = channelCount
        ? static_cast<uint32_t>((channelCount + SingleChannelCapacity - 1) /
                                SingleChannelCapacity)
        : 1;
    if (!chunkCount ||
        size_t(selectedCount) * chunkCount > MaxJobs / selectedBSSIDCount)
        return {EOVERFLOW, bssidCount > 1
            ? ScanMultipleBridge::NativeBSSIDCount
            : ScanMultipleBridge::NativeChannelCount};

    clearPlan(jobs);
    uint32_t output = 0;
    for (uint32_t i = 0; i < selectedCount; ++i) {
      for (uint32_t chunk = 0; chunk < chunkCount; ++chunk) {
        for (uint32_t bssidIndex = 0; bssidIndex < selectedBSSIDCount; ++bssidIndex) {
            uint8_t *single = jobs + size_t(output++) * SingleScanSize;
            write32(single + SingleVersion, 1);
            write32(single + SingleAPMode, apMode);
            if (selectedBSSIDs[bssidIndex] != 0xff)
                memcpy(single + SingleBSSID,
                       native + ScanMultipleBridge::NativeBSSIDArray +
                           size_t(selectedBSSIDs[bssidIndex]) * 6, 6);

            if (selected[i] != 0xff) {
                const size_t record = ScanMultipleBridge::NativeSSIDArray + size_t(selected[i]) *
                    ScanMultipleBridge::SSIDStride;
                const uint32_t length = ScanCompat::read32(native + record +
                                                           ScanMultipleBridge::SSIDLengthOffset);
                write32(single + SingleSSIDLength, length);
                memcpy(single + SingleSSID,
                       native + record + ScanMultipleBridge::SSIDBytesOffset, length);
            }

            write32(single + SingleScanType, scanType);
            write32(single + SinglePhyMode, phyMode);
            ScanCompat::write16(single + SingleDwellTime, static_cast<uint16_t>(dwellTime));
            write32(single + SingleRestTime, restTime);
            const uint32_t channelOffset = chunk * SingleChannelCapacity;
            const uint32_t channelsThisChunk = channelCount > channelOffset
                ? static_cast<uint32_t>(channelCount - channelOffset < SingleChannelCapacity
                    ? channelCount - channelOffset : SingleChannelCapacity)
                : 0;
            write32(single + SingleChannelCount, channelsThisChunk);
            if (channelsThisChunk)
                memcpy(single + SingleChannels,
                       native + ScanMultipleBridge::NativeChannels +
                           size_t(channelOffset) * ScanMultipleBridge::ChannelStride,
                       size_t(channelsThisChunk) * ScanMultipleBridge::ChannelStride);
        }
      }
    }
    *jobCount = output;
    return {0, 0};
}

enum class State : uint8_t {
    Idle,
    StartQueued,
    InFlight,
    CancelledInFlight,
    FinishQueued,
    Publishing
};

using Deferred = void (*)(void *owner, uint64_t generation);

// Protected by the provider session's registry lock. Owner exit cancellation
// is generation-scoped; lifecycle retirement remains a separate sticky reason
// and is never overwritten by a later owner request.
class PendingCancellation {
public:
    bool requestOwner(uint64_t generation) {
        if (ownerPending_ && ownerGeneration_ != generation) return false;
        ownerPending_ = true;
        ownerGeneration_ = generation;
        return true;
    }

    bool ownerPending() const { return ownerPending_; }
    uint64_t ownerGeneration() const { return ownerGeneration_; }

    // A worker that starts during a submit reservation leaves the request
    // pending. finishSubmitting() will enqueue it again after dropping the
    // reservation. Retirement has its own sticky flag and always cancels the
    // whole session once the reservation is gone.
    bool claim(bool submitting, bool retiring, uint64_t *generation,
               bool *cancelAll) const {
        if (!generation || !cancelAll || submitting) return false;
        if (retiring) {
            *generation = 0;
            *cancelAll = true;
            return true;
        }
        if (!ownerPending_) return false;
        *generation = ownerGeneration_;
        *cancelAll = false;
        return true;
    }

    bool completeOwner(uint64_t generation) {
        if (!ownerPending_ || ownerGeneration_ != generation) return false;
        ownerPending_ = false;
        ownerGeneration_ = 0;
        return true;
    }

    void clear() {
        ownerPending_ = false;
        ownerGeneration_ = 0;
    }

private:
    bool ownerPending_ = false;
    uint64_t ownerGeneration_ = 0;
};

constexpr size_t MaxCancelledOwners = 16;

// PID tombstones prevent a cancelled provider request node from becoming
// visible to a later process that reuses its PID. Access is serialized by the
// provider session's registry lock. A successful managed start for the same
// PID replaces that provider node and is the only operation that removes it.
class CancelledOwners {
public:
    bool contains(int pid) const {
        if (pid <= 0) return false;
        for (size_t i = 0; i < count_; ++i) if (pids_[i] == pid) return true;
        return false;
    }

    bool canAdd(int pid) const {
        return pid > 0 && (contains(pid) || count_ < MaxCancelledOwners);
    }

    bool add(int pid) {
        if (!canAdd(pid)) return false;
        if (contains(pid)) return true;
        pids_[count_++] = pid;
        return true;
    }

    // The El Cap manager replaces its per-PID request node only after a
    // successful first startScan. Keep the tombstone on Store admission or
    // provider-start failure so a later GET11 cannot reveal an older node.
    bool clearAfterSuccessfulFirstStart(int pid, bool aggregateBegan,
                                        bool providerStartSucceeded) {
        if (!aggregateBegan || !providerStartSucceeded) return false;
        return remove(pid);
    }

    size_t count() const { return count_; }

    void clear() {
        memset(pids_, 0, sizeof(pids_));
        count_ = 0;
    }

private:
    bool remove(int pid) {
        for (size_t i = 0; i < count_; ++i) if (pids_[i] == pid) {
            pids_[i] = pids_[--count_];
            pids_[count_] = 0;
            return true;
        }
        return false;
    }

    int pids_[MaxCancelledOwners] {};
    size_t count_ = 0;
};

struct CompletionTicket {
    uint64_t generation = 0;
    uint64_t startToken = 0;

    bool valid() const { return generation != 0 && startToken != 0; }
};

enum class CompletionKind : uint8_t {
    Advance,
    Failure
};

struct CompletionRecord {
    CompletionTicket ticket {};
    CompletionKind kind = CompletionKind::Advance;
};

constexpr size_t MaxPendingCompletions = 8;

// Fixed-capacity completion handoff. Callers provide their own lock. Events
// for the same provider-start token coalesce; a context violation upgrades an
// already queued advance. Overflow fails the current token closed.
class PendingCompletions {
public:
    bool enqueue(const CompletionTicket &ticket, CompletionKind kind) {
        if (!ticket.valid()) return false;
        for (size_t offset = 0; offset < count_; ++offset) {
            CompletionRecord &record = records_[(head_ + offset) % MaxPendingCompletions];
            if (sameTicket(record.ticket, ticket)) {
                if (kind == CompletionKind::Failure) record.kind = kind;
                return true;
            }
        }
        if (count_ == MaxPendingCompletions) {
            clear();
            kind = CompletionKind::Failure;
        }
        records_[(head_ + count_) % MaxPendingCompletions] = {ticket, kind};
        ++count_;
        return true;
    }

    bool pop(CompletionRecord *record) {
        if (!record || !count_) return false;
        *record = records_[head_];
        records_[head_] = {};
        head_ = (head_ + 1) % MaxPendingCompletions;
        --count_;
        if (!count_) head_ = 0;
        return true;
    }

    bool pending() const { return count_ != 0; }
    size_t count() const { return count_; }

    void clear() {
        memset(records_, 0, sizeof(records_));
        head_ = count_ = 0;
    }

private:
    static bool sameTicket(const CompletionTicket &left,
                           const CompletionTicket &right) {
        return left.generation == right.generation &&
            left.startToken == right.startToken;
    }

    CompletionRecord records_[MaxPendingCompletions] {};
    size_t head_ = 0;
    size_t count_ = 0;
};

struct API {
    void *context = nullptr;
    Lock lock {};
    void *(*allocate)(size_t) = nullptr;
    void (*deallocate)(void *, size_t) = nullptr;
    // Run the initial start synchronously under the ScanManager IOWorkLoop
    // gate so its immediate errno can be returned to the SET86 caller. On an
    // error, return without invoking callback; on success, wait for callback.
    int (*runOnGate)(void *context, Deferred callback, void *owner,
                    uint64_t generation) = nullptr;
    // Must enqueue asynchronously on the manager's IOWorkLoop gate. It must
    // not invoke the callback inline and must not invoke it if returning error.
    int (*schedule)(void *context, Deferred callback, void *owner,
                    uint64_t generation) = nullptr;
    // Calls the audited ElCap IO80211ScanManager::startScan(manager, data).
    int (*startSingle)(void *context, void *manager,
                       const uint8_t *request, size_t requestSize) = nullptr;
    // Snapshots every completed legacy manager result into owner-controlled
    // storage before the next child start clears that PID's request node.
    // Called on the manager's WorkLoop gate after the original code-10 path
    // has completed its GET11/cache updates.
    int (*snapshotCompleted)(void *context, void *interface,
                             void *manager) = nullptr;
    // Marks the managed GET11 snapshot set complete. On an error the set must
    // expose that error instead of a partial successful scan.
    void (*finishAggregate)(void *context, int error) = nullptr;
    // Publishes via the saved, unhooked event-router output selected for this
    // interface (BSD or datapath); must bypass suppressExternalEvent.
    void (*publishFinalEvent)(void *context, void *interface,
                              uint32_t eventCode) = nullptr;
    void (*reportFailure)(void *context, void *interface, int error) = nullptr;
};

// Per-provider coordinator. submit() may be called from the request path, but
// highLevelPostMessageReturned(), cancel(), and event-router filters must be
// serialized on the provider's manager IOWorkLoop gate. The lock protects
// state snapshots; start/publish/schedule callbacks run outside it. The owner
// must keep this object alive until cancellation and any in-flight SET10
// completion have drained.
class Coordinator {
public:
    Coordinator() = default;
    explicit Coordinator(const API &api) : api_(api), apiReady_(true) {}
    Coordinator(const Coordinator &) = delete;
    Coordinator &operator=(const Coordinator &) = delete;

    bool prepare(const API &api) {
        if (apiReady_ || !api.lock.value || !api.lock.enter || !api.lock.leave ||
            !api.allocate || !api.deallocate || !api.runOnGate || !api.schedule ||
            !api.startSingle || !api.snapshotCompleted || !api.finishAggregate ||
            !api.publishFinalEvent ||
            state_ != State::Idle) return false;
        api_ = api;
        apiReady_ = true;
        return true;
    }

    bool ready() const {
        return apiReady_ && api_.lock.value && api_.lock.enter && api_.lock.leave &&
            api_.allocate && api_.deallocate && api_.runOnGate && api_.schedule &&
            api_.startSingle && api_.snapshotCompleted && api_.finishAggregate &&
            api_.publishFinalEvent;
    }

    // Input is already kernel-owned and bounded by the outer SET86 copyIn.
    int submit(void *interface, void *manager, const uint8_t *native,
               size_t nativeSize, bool *firstProviderStartSucceeded = nullptr) {
        if (firstProviderStartSucceeded) *firstProviderStartSucceeded = false;
        if (!ready()) return ENXIO;
        if (!interface || !manager || !native) return EINVAL;
        uint8_t *newJobs = static_cast<uint8_t *>(api_.allocate(MaxJobs * SingleScanSize));
        if (!newJobs) return ENOMEM;
        uint32_t count = 0;
        const auto built = build43224Plan(native, nativeSize, newJobs,
                                          MaxJobs * SingleScanSize, &count);
        if (built.error) {
            memset(newJobs, 0, MaxJobs * SingleScanSize);
            api_.deallocate(newJobs, MaxJobs * SingleScanSize);
            return built.error;
        }

        uint64_t generation = 0;
        api_.lock.enter(api_.lock.value);
        if (state_ != State::Idle) {
            api_.lock.leave(api_.lock.value);
            memset(newJobs, 0, MaxJobs * SingleScanSize);
            api_.deallocate(newJobs, MaxJobs * SingleScanSize);
            return EBUSY;
        }
        jobs_ = newJobs;
        count_ = count;
        index_ = 0;
        interface_ = interface;
        manager_ = manager;
        generation_ = nextGeneration(generation_);
        generation = generation_;
        initialStartGeneration_ = generation;
        initialStartAttempted_ = false;
        initialStartPending_ = true;
        initialStartError_ = 0;
        deferredFailureError_ = 0;
        state_ = State::StartQueued;
        api_.lock.leave(api_.lock.value);

        const int error = api_.runOnGate(api_.context, &Coordinator::scheduledStart,
                                         this, generation);
        if (error) {
            uint8_t *discard = nullptr;
            api_.lock.enter(api_.lock.value);
            if (generation_ == generation && state_ == State::StartQueued) {
                initialStartPending_ = false;
                discard = detachLocked();
            }
            api_.lock.leave(api_.lock.value);
            releaseJobs(discard);
            return error;
        }
        api_.lock.enter(api_.lock.value);
        const bool attempted = initialStartGeneration_ == generation &&
            initialStartAttempted_;
        const int startError = attempted ? initialStartError_ : ECANCELED;
        if (firstProviderStartSucceeded)
            *firstProviderStartSucceeded = attempted && startError == 0;
        api_.lock.leave(api_.lock.value);
        return startError;
    }

    bool suppressExternalEvent(void *interface, uint32_t eventCode) const {
        if (!ready()) return false;
        if (eventCode != ScanDoneEvent && eventCode != ScanManagerDoneEvent) return false;
        api_.lock.enter(api_.lock.value);
        const bool suppress = interface_ == interface && state_ != State::Idle;
        api_.lock.leave(api_.lock.value);
        return suppress;
    }

    // Invoke only after the original high-level IO80211Interface::postMessage
    // returned. For code 10 this means ScanManager::scanDone(true) has already
    // drained GET11 and updated its existing BSSID-keyed cache; nested code 15
    // performs the manager cleanup before this callback runs.
    void highLevelPostMessageReturned(void *interface, uint32_t eventCode,
                                      uint64_t expectedGeneration = 0,
                                      uint64_t expectedStartToken = 0) {
        if (!ready() || eventCode != ScanDoneEvent) return;
        uint64_t generation = 0;
        void *manager = nullptr;
        bool finalize = false;
        api_.lock.enter(api_.lock.value);
        if (interface_ != interface || state_ == State::Idle ||
            (expectedGeneration && generation_ != expectedGeneration) ||
            (expectedStartToken && activeStartToken_ != expectedStartToken)) {
            api_.lock.leave(api_.lock.value);
            return;
        }
        if (state_ == State::CancelledInFlight) {
            cancelCompletionSeen_ = true;
            uint8_t *discard = nullptr;
            if (!startSingleActive_) discard = detachLocked();
            api_.lock.leave(api_.lock.value);
            releaseJobs(discard);
            return;
        }
        if (state_ != State::InFlight) {
            api_.lock.leave(api_.lock.value);
            return;
        }
        manager = manager_;
        generation = generation_;
        api_.lock.leave(api_.lock.value);

        // getScanResult is PID keyed, and the next startScan clears the old
        // request node for that PID. Drain and copy its results before the
        // following child starts.
        const int snapshotError = api_.snapshotCompleted(
            api_.context, interface, manager);

        api_.lock.enter(api_.lock.value);
        if (interface_ != interface || generation_ != generation ||
            (expectedStartToken && activeStartToken_ != expectedStartToken) ||
            state_ != State::InFlight) {
            api_.lock.leave(api_.lock.value);
            return;
        }

        if (snapshotError) {
            index_ = count_;
            state_ = State::FinishQueued;
            finishFallback_ = false;
            pendingFinishError_ = snapshotError;
            api_.lock.leave(api_.lock.value);
            const int scheduleError = api_.schedule(
                api_.context, &Coordinator::scheduledFinish, this, generation);
            if (scheduleError) {
                api_.lock.enter(api_.lock.value);
                if (generation_ == generation && state_ == State::FinishQueued) {
                    finishFallback_ = true;
                    pendingFinishError_ = snapshotError;
                    if (!startSingleActive_) {
                        state_ = State::Publishing;
                        finalize = true;
                    }
                }
                api_.lock.leave(api_.lock.value);
                if (finalize) publishAndClear(generation, snapshotError);
            }
            return;
        }

        ++index_;
        generation = generation_;
        if (index_ >= count_) {
            state_ = State::FinishQueued;
            finishFallback_ = false;
            pendingFinishError_ = 0;
        } else {
            state_ = State::StartQueued;
        }
        api_.lock.leave(api_.lock.value);

        if (state() == State::FinishQueued) {
            const int error = api_.schedule(api_.context, &Coordinator::scheduledFinish,
                                            this, generation);
            if (error) {
                api_.lock.enter(api_.lock.value);
                if (generation_ == generation && state_ == State::FinishQueued) {
                    finishFallback_ = true;
                    pendingFinishError_ = error;
                    if (!startSingleActive_) {
                        state_ = State::Publishing;
                        finalize = true;
                    }
                }
                api_.lock.leave(api_.lock.value);
                if (finalize) publishAndClear(generation, error);
            }
            return;
        }
        const int error = api_.schedule(api_.context, &Coordinator::scheduledStart,
                                        this, generation);
        if (error) {
            api_.lock.enter(api_.lock.value);
            if (generation_ == generation && state_ == State::StartQueued) {
                state_ = State::FinishQueued;
                finishFallback_ = true;
                pendingFinishError_ = error;
                if (!startSingleActive_) state_ = State::Publishing;
            }
            const bool owns = generation_ == generation && state_ == State::Publishing;
            api_.lock.leave(api_.lock.value);
            if (owns) publishAndClear(generation, error);
        }
    }

    // Cancellation must be called when the provider is stopped on its
    // workloop/gate. An active hardware scan keeps its generation so a queued
    // completion can drain it; a deferred next-scan callback is invalidated
    // when its StartQueued state is detached.
    void cancel(void *interface) {
        cancelMatching(interface, 0);
    }

    // Used for owner-exit work that may be delayed past the current child.
    // A stale work item cannot cancel a later scan on the same interface.
    void cancelGeneration(void *interface, uint64_t expectedGeneration) {
        if (expectedGeneration) cancelMatching(interface, expectedGeneration);
    }

    uint64_t activeGeneration(void *interface) const {
        if (!ready() || !interface) return 0;
        api_.lock.enter(api_.lock.value);
        const uint64_t value = interface_ == interface && state_ != State::Idle
            ? generation_ : 0;
        api_.lock.leave(api_.lock.value);
        return value;
    }

    bool captureCompletionTicket(void *interface, CompletionTicket *ticket) const {
        if (!ready() || !interface || !ticket) return false;
        *ticket = {};
        api_.lock.enter(api_.lock.value);
        const bool active = interface_ == interface && activeStartToken_ &&
            (state_ == State::InFlight || state_ == State::CancelledInFlight);
        if (active) {
            ticket->generation = generation_;
            ticket->startToken = activeStartToken_;
        }
        api_.lock.leave(api_.lock.value);
        return active;
    }

private:
    void cancelMatching(void *interface, uint64_t expectedGeneration) {
        if (!ready()) return;
        uint8_t *discard = nullptr;
        api_.lock.enter(api_.lock.value);
        if (interface_ == interface && state_ != State::Idle &&
            (!expectedGeneration || generation_ == expectedGeneration)) {
            if (state_ == State::CancelledInFlight) {
                // A duplicate or delayed cancel must not detach an already
                // cancelled request or erase a completion observed while its
                // first start callback is still active.
            } else if (startSingleActive_) {
                // The currently executing start callback owns the request
                // buffer and will drain this cancellation before returning.
                // Keep its generation so an already queued completion can
                // still drain the cancelled in-flight start.
                state_ = State::CancelledInFlight;
                cancelCompletionSeen_ = false;
            } else if (state_ == State::InFlight) {
                // No next child is queued while a child is InFlight. Preserve
                // this generation so pending completion tickets remain valid.
                state_ = State::CancelledInFlight;
                cancelCompletionSeen_ = false;
            } else {
                generation_ = nextGeneration(generation_);
                discard = detachLocked();
            }
        }
        api_.lock.leave(api_.lock.value);
        releaseJobs(discard);
    }

public:
    // Used when the event router cannot safely mirror a completion from an
    // interrupt/interrupts-disabled context. The original event has already
    // run, so stop the queue without fabricating another event pair; managed
    // GET11 reports the explicit error instead of a partial union.
    void failCurrent(void *interface, int error,
                     uint64_t expectedGeneration = 0,
                     uint64_t expectedStartToken = 0) {
        if (!ready() || !interface || !error) return;
        uint8_t *discard = nullptr;
        uint64_t generation = 0;
        bool deferred = false;
        api_.lock.enter(api_.lock.value);
        if (interface_ == interface && state_ != State::Idle &&
            state_ != State::StartQueued &&
            (!expectedGeneration || generation_ == expectedGeneration) &&
            (!expectedStartToken || activeStartToken_ == expectedStartToken)) {
            if (startSingleActive_) {
                // The provider may still be reading this job buffer. Record a
                // terminal error and defer detaching until startSingle returns.
                state_ = State::CancelledInFlight;
                cancelCompletionSeen_ = true;
                if (!deferredFailureError_) deferredFailureError_ = error;
                deferred = true;
            } else {
                generation_ = nextGeneration(generation_);
                generation = generation_;
                discard = detachLocked();
            }
        }
        api_.lock.leave(api_.lock.value);
        releaseJobs(discard);
        if (!generation || deferred) return;
        api_.finishAggregate(api_.context, error);
        if (api_.reportFailure) api_.reportFailure(api_.context, interface, error);
    }

public:
    bool aggregateReady() const { return ready(); }
    State state() const {
        if (!ready()) return State::Idle;
        api_.lock.enter(api_.lock.value);
        const State value = state_;
        api_.lock.leave(api_.lock.value);
        return value;
    }

private:
    static uint64_t nextGeneration(uint64_t value) {
        ++value;
        return value ? value : 1;
    }

    static void scheduledStart(void *owner, uint64_t generation) {
        static_cast<Coordinator *>(owner)->startScheduled(generation);
    }

    static void scheduledFinish(void *owner, uint64_t generation) {
        static_cast<Coordinator *>(owner)->finishScheduled(generation);
    }

    uint8_t *detachLocked() {
        uint8_t *bytes = jobs_;
        jobs_ = nullptr;
        count_ = 0;
        index_ = 0;
        interface_ = nullptr;
        manager_ = nullptr;
        initialStartPending_ = false;
        startSingleActive_ = false;
        cancelCompletionSeen_ = false;
        activeStartToken_ = 0;
        deferredFailureError_ = 0;
        finishFallback_ = false;
        pendingFinishError_ = 0;
        state_ = State::Idle;
        return bytes;
    }

    void releaseJobs(uint8_t *bytes) {
        if (!bytes) return;
        memset(bytes, 0, MaxJobs * SingleScanSize);
        api_.deallocate(bytes, MaxJobs * SingleScanSize);
    }

    void startScheduled(uint64_t generation) {
        void *manager = nullptr;
        const uint8_t *request = nullptr;
        api_.lock.enter(api_.lock.value);
        if (generation_ != generation || state_ != State::StartQueued ||
            !jobs_ || index_ >= count_) {
            api_.lock.leave(api_.lock.value);
            return;
        }
        manager = manager_;
        request = jobs_ + size_t(index_) * SingleScanSize;
        const bool initialStart = initialStartPending_;
        initialStartPending_ = false;
        startTokenCounter_ = nextGeneration(startTokenCounter_);
        activeStartToken_ = startTokenCounter_;
        startSingleActive_ = true;
        state_ = State::InFlight;
        api_.lock.leave(api_.lock.value);

        const int error = api_.startSingle(api_.context, manager, request, SingleScanSize);
        uint8_t *discard = nullptr;
        bool finalize = false;
        bool finalizeFailure = false;
        int finalError = 0;
        void *failedInterface = nullptr;
        api_.lock.enter(api_.lock.value);
        if (initialStart && initialStartGeneration_ == generation) {
            initialStartAttempted_ = true;
            initialStartError_ = error;
        }
        if (generation_ == generation) {
            startSingleActive_ = false;
            if (state_ == State::CancelledInFlight) {
                // A successful manager start may still be using the request
                // and retained interface until its code-10 completion. Keep
                // both alive unless that event already drained reentrantly.
                if (deferredFailureError_) {
                    failedInterface = interface_;
                    finalError = deferredFailureError_;
                    discard = detachLocked();
                    finalizeFailure = true;
                } else if (error || cancelCompletionSeen_) {
                    discard = detachLocked();
                }
            } else if (error && state_ == State::InFlight) {
                if (initialStart) {
                    discard = detachLocked();
                } else {
                    state_ = State::Publishing;
                    finalError = error;
                    finalize = true;
                }
            } else if (state_ == State::FinishQueued && finishFallback_) {
                state_ = State::Publishing;
                finalError = pendingFinishError_;
                finalize = true;
            }
        }
        api_.lock.leave(api_.lock.value);
        releaseJobs(discard);
        if (finalizeFailure) {
            api_.finishAggregate(api_.context, finalError);
            if (api_.reportFailure)
                api_.reportFailure(api_.context, failedInterface, finalError);
        }
        if (finalize) publishAndClear(generation, finalError);
    }

    void finishScheduled(uint64_t generation) {
        int error = 0;
        bool finalize = false;
        api_.lock.enter(api_.lock.value);
        if (generation_ == generation && state_ == State::FinishQueued) {
            state_ = State::Publishing;
            error = pendingFinishError_;
            finalize = true;
        }
        api_.lock.leave(api_.lock.value);
        if (finalize) publishAndClear(generation, error);
    }

    void publishAndClear(uint64_t generation, int error) {
        void *interface = nullptr;
        api_.lock.enter(api_.lock.value);
        if (generation_ != generation || state_ != State::Publishing) {
            api_.lock.leave(api_.lock.value);
            return;
        }
        interface = interface_;
        api_.lock.leave(api_.lock.value);

        if (error && api_.reportFailure)
            api_.reportFailure(api_.context, interface, error);
        api_.finishAggregate(api_.context, error);
        // The callback uses the saved event-router output, bypassing the
        // suppressor. Results from all completed children are already merged.
        api_.publishFinalEvent(api_.context, interface, ScanDoneEvent);
        api_.publishFinalEvent(api_.context, interface, ScanManagerDoneEvent);

        uint8_t *discard = nullptr;
        api_.lock.enter(api_.lock.value);
        if (generation_ == generation && state_ == State::Publishing)
            discard = detachLocked();
        api_.lock.leave(api_.lock.value);
        releaseJobs(discard);
    }

    API api_;
    bool apiReady_ = false;
    State state_ = State::Idle;
    uint64_t generation_ = 0;
    uint64_t initialStartGeneration_ = 0;
    uint64_t startTokenCounter_ = 0;
    uint64_t activeStartToken_ = 0;
    uint32_t count_ = 0;
    uint32_t index_ = 0;
    void *interface_ = nullptr;
    void *manager_ = nullptr;
    uint8_t *jobs_ = nullptr;
    bool initialStartPending_ = false;
    bool initialStartAttempted_ = false;
    bool startSingleActive_ = false;
    bool cancelCompletionSeen_ = false;
    bool finishFallback_ = false;
    int initialStartError_ = 0;
    int deferredFailureError_ = 0;
    int pendingFinishError_ = 0;
};

} // namespace ScanSequence
} // namespace LegacyWiFi

#endif
