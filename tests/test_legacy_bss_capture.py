"""Sanitizer-backed tests for owned BSS producer snapshots and registry tokens."""
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/bss_capture.hpp"

#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <type_traits>

namespace C = LegacyWiFi::BSSCapture;
namespace B = LegacyWiFi::CurrentBSS;
namespace N = LegacyWiFi::NetworkMatch;
namespace A = LegacyWiFi::NetworkAssurance;

namespace LegacyWiFi { namespace BSSCapture {
struct TestAccess {
    static void setNextNonce(Registry &registry, uint64_t nonce) {
        registry.nextNonce_ = nonce;
    }
    static bool poisoned(const Registry &registry) {
        return registry.noncePoisoned_;
    }
};
} }

static_assert(!std::is_copy_constructible<C::Ticket>::value, "ticket cannot copy");
static_assert(!std::is_copy_assignable<C::Ticket>::value, "ticket cannot copy assign");
static_assert(!std::is_move_constructible<C::Ticket>::value, "ticket cannot move");
static_assert(!std::is_move_assignable<C::Ticket>::value, "ticket cannot move assign");
static_assert(!std::is_copy_constructible<C::Registry>::value, "registry cannot copy");
static_assert(!std::is_move_constructible<C::Registry>::value, "registry cannot move");

static void write64(uint8_t *p, uint64_t n) { std::memcpy(p, &n, sizeof(n)); }
static void write16(uint8_t *p, uint16_t n) { std::memcpy(p, &n, sizeof(n)); }

static void initRecord(uint8_t *record, const uint8_t *ssid, size_t ssidLength,
                       uint16_t capability = 1) {
    std::memset(record, 0, B::Record4331Size);
    const uint8_t bssid[B::BSSIDSize] = {0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee};
    std::memcpy(record, bssid, sizeof(bssid));
    record[B::SSIDLengthOffset] = static_cast<uint8_t>(ssidLength);
    if (ssidLength) std::memcpy(record + B::SSIDOffset, ssid, ssidLength);
    // Deliberately nonzero: DTIM is not part of the identity fingerprint.
    record[0x60] = 9;
    write16(record + B::Capability4331Offset, capability);
}

static size_t makeBody(uint8_t *body, uint16_t capability,
                       bool includeRsn, bool includeCCX = false) {
    std::memset(body, 0, B::MaximumBeaconBodyBytes);
    write16(body + 10, capability);
    size_t length = B::BeaconFixedBodyBytes;
    if (includeRsn) {
        const uint8_t rsn[] = {48, 2, 1, 0};
        std::memcpy(body + length, rsn, sizeof(rsn));
        length += sizeof(rsn);
    }
    if (includeCCX) {
        const uint8_t ccx[] = {221, 5, 0x00, 0x40, 0x96, 0x0b, 0x80};
        std::memcpy(body + length, ccx, sizeof(ccx));
        length += sizeof(ccx);
    }
    return length;
}

static B::OwnedSnapshot decoded(uint8_t *record, size_t recordSize,
                                const uint8_t *body, size_t bodySize) {
    B::OwnedSnapshot value {};
    assert(C::decodeProduced4331(record, recordSize, body, bodySize, &value) == 0);
    return value;
}

static bool sameSnapshot(const B::OwnedSnapshot &a, const B::OwnedSnapshot &b) {
    return std::memcmp(a.bssid, b.bssid, sizeof(a.bssid)) == 0 &&
        a.network.ssidLength == b.network.ssidLength &&
        std::memcmp(a.network.ssid, b.network.ssid, N::MaximumSSIDLength) == 0 &&
        a.network.encryptionModes == b.network.encryptionModes &&
        a.network.apMode == b.network.apMode && a.network.fils == b.network.fils &&
        a.networkAssurance == b.networkAssurance;
}

static B::OwnedSnapshot sentinelSnapshot() {
    B::OwnedSnapshot value {};
    value.bssid[0] = 2;
    value.bssid[1] = 0x5a;
    value.network.ssid[0] = 0xa5;
    value.network.ssidLength = 1;
    value.network.encryptionModes = 0x1234;
    value.network.apMode = 3;
    value.network.fils = N::FILS::Unknown;
    value.networkAssurance = A::State::Enabled;
    return value;
}

static C::Fingerprint getFingerprint(const uint8_t *record) {
    C::Fingerprint value {};
    assert(C::fingerprint(record, B::Record4331Size, &value));
    return value;
}

static void test_fingerprint_fields_and_output_unchanged() {
    const uint8_t ssid[] = {'n', 0, 'w'};
    uint8_t record[B::Record4331Size], changed[B::Record4331Size];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    C::Fingerprint first = getFingerprint(record);
    record[0x60] ^= 0xff; // DTIM must not participate.
    record[0x30] = 0x77; // Unrelated scan metadata must not participate.
    write16(record + B::Capability4331Offset, 0x11 | 0x400 | 0x20);
    // Short-slot and other capability flags do not affect NetworkIdentity.
    C::Fingerprint second = getFingerprint(record);
    assert(C::sameFingerprint(first, second));
    assert(first.capability == 0x11);

    const uint16_t identityChanges[] = {0x10, 0x02, 0x01};
    for (uint16_t bit : identityChanges) {
        std::memcpy(changed, record, sizeof(changed));
        write16(changed + B::Capability4331Offset, 0x11 ^ bit);
        C::Fingerprint changedCapability = getFingerprint(changed);
        assert(!C::sameFingerprint(first, changedCapability));
    }

    std::memcpy(changed, record, sizeof(changed));
    write16(changed + B::Capability4331Offset, 0x11);
    std::memcpy(record, changed, sizeof(record));
    record[B::SSIDOffset + 1] = 'x';
    C::Fingerprint changedSSID = getFingerprint(record);
    assert(!C::sameFingerprint(first, changedSSID));

    C::Fingerprint unchanged = first;
    assert(!C::fingerprint(nullptr, B::Record4331Size, &unchanged));
    assert(C::sameFingerprint(first, unchanged));
    assert(!C::fingerprint(record, B::Record4331Size - 1, &unchanged));
    assert(C::sameFingerprint(first, unchanged));
    record[B::SSIDLengthOffset] = 33;
    assert(!C::fingerprint(record, B::Record4331Size, &unchanged));
    assert(C::sameFingerprint(first, unchanged));
}

static void test_decode_produced_full_body_without_mutation() {
    const uint8_t ssid[] = {'w', 'i', 0, 'f', 'i'};
    uint8_t record[B::Record4331Size];
    uint8_t body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true, true);
    uint8_t recordBefore[B::Record4331Size];
    uint8_t bodyBefore[B::MaximumBeaconBodyBytes];
    std::memcpy(recordBefore, record, sizeof(recordBefore));
    std::memcpy(bodyBefore, body, sizeof(bodyBefore));

    B::OwnedSnapshot result {};
    assert(C::decodeProduced4331(record, sizeof(record), body, bodySize, &result) == 0);
    assert(std::memcmp(result.bssid, record, B::BSSIDSize) == 0);
    assert(result.network.ssidLength == sizeof(ssid));
    assert(std::memcmp(result.network.ssid, ssid, sizeof(ssid)) == 0);
    assert(result.network.encryptionModes == 8);
    assert(result.network.apMode == 2);
    assert(result.network.fils == N::FILS::Absent);
    assert(result.networkAssurance == A::State::Enabled);
    assert(std::memcmp(recordBefore, record, sizeof(record)) == 0);
    assert(std::memcmp(bodyBefore, body, sizeof(body)) == 0);

    // The identity fingerprint masks non-identity capability flags, while
    // producer decoding still requires the parser's full raw word to match.
    initRecord(record, ssid, sizeof(ssid), 0x411);
    const size_t shortSlotBodySize = makeBody(body, 0x411, true, false);
    B::OwnedSnapshot shortSlot = decoded(record, sizeof(record), body,
                                         shortSlotBodySize);
    C::Fingerprint shortSlotFingerprint = getFingerprint(record);
    assert(shortSlotFingerprint.capability == 0x11);
    assert(shortSlot.network.apMode == result.network.apMode);
    assert(shortSlot.network.encryptionModes == result.network.encryptionModes);

    initRecord(record, ssid, sizeof(ssid), 0x11);

    // A complete body with no CCX still yields a valid identity and Unknown.
    const size_t noCCXSize = makeBody(body, 0x11, true, false);
    B::OwnedSnapshot noCCX = decoded(record, sizeof(record), body, noCCXSize);
    assert(noCCX.network.encryptionModes == 8);
    assert(noCCX.networkAssurance == A::State::Unknown);

    // A 12-byte fixed body with no IE tail is known input, not an absent body.
    const size_t fixedOnlySize = makeBody(body, 0x11, false, false);
    B::OwnedSnapshot fixedOnly = decoded(record, sizeof(record), body, fixedOnlySize);
    assert(fixedOnly.network.encryptionModes == 2);
    assert(fixedOnly.networkAssurance == A::State::Unknown);

    // The maximum legal full body is 12 fixed bytes plus 1024 IE bytes.
    std::memset(body, 0, sizeof(body));
    write16(body + 10, 0x11);
    size_t cursor = B::BeaconFixedBodyBytes;
    while (cursor < sizeof(body)) {
        body[cursor++] = 0; // Unknown element ID.
        body[cursor++] = 0; // Empty body.
    }
    B::OwnedSnapshot maximum = decoded(record, sizeof(record), body, sizeof(body));
    assert(maximum.networkAssurance == A::State::Unknown);
}

static void expectDecodeFailure(uint8_t *record, size_t recordSize,
                                const uint8_t *body, size_t bodySize, int error) {
    B::OwnedSnapshot out = sentinelSnapshot();
    const B::OwnedSnapshot before = out;
    assert(C::decodeProduced4331(record, recordSize, body, bodySize, &out) == error);
    assert(sameSnapshot(out, before));
}

static void test_decode_produced_rejects_invalid_shapes() {
    const uint8_t ssid[] = {'x'};
    uint8_t record[B::Record4331Size];
    uint8_t body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    size_t bodySize = makeBody(body, 0x11, false);

    expectDecodeFailure(nullptr, sizeof(record), body, bodySize, EINVAL);
    expectDecodeFailure(record, sizeof(record) - 1, body, bodySize, EINVAL);
    expectDecodeFailure(record, sizeof(record), nullptr, bodySize, EINVAL);
    expectDecodeFailure(record, sizeof(record), body, 0, EOPNOTSUPP);
    expectDecodeFailure(record, sizeof(record), body, B::BeaconFixedBodyBytes - 1, EINVAL);
    expectDecodeFailure(record, sizeof(record), body, B::MaximumBeaconBodyBytes + 1, EOVERFLOW);
    const auto wrapped = reinterpret_cast<const uint8_t *>(UINTPTR_MAX - 4);
    expectDecodeFailure(record, sizeof(record), wrapped,
                        B::BeaconFixedBodyBytes, EINVAL);

    // Parser output must be bodyless; a pointer/length pair cannot be smuggled
    // through the synthetic-record decoder.
    write64(record + B::IEPointerOffset, 0x1234);
    expectDecodeFailure(record, sizeof(record), body, bodySize, EINVAL);
    write64(record + B::IEPointerOffset, 0);
    write16(record + B::IELengthOffset, 2);
    expectDecodeFailure(record, sizeof(record), body, bodySize, EINVAL);
    write16(record + B::IELengthOffset, 0);

    // The parser's fixed capability must agree with the raw Beacon body.
    makeBody(body, 0x12, false);
    expectDecodeFailure(record, sizeof(record), body, B::BeaconFixedBodyBytes, EINVAL);

    // Equality is over the entire capability word, even when only a
    // non-identity flag differs.
    makeBody(body, 0x411, false);
    expectDecodeFailure(record, sizeof(record), body, B::BeaconFixedBodyBytes, EINVAL);

    // Malformed bytes in the IE tail fail; identical-looking fixed-header
    // bytes do not get parsed as IEs.
    makeBody(body, 0x11, false);
    body[B::BeaconFixedBodyBytes] = 48;
    body[B::BeaconFixedBodyBytes + 1] = 4;
    body[B::BeaconFixedBodyBytes + 2] = 0;
    expectDecodeFailure(record, sizeof(record), body, B::BeaconFixedBodyBytes + 3, EINVAL);

    initRecord(record, ssid, sizeof(ssid), 0x11);
    std::memset(body, 0, B::BeaconFixedBodyBytes);
    body[0] = 48; body[1] = 2;
    body[4] = 221; body[5] = 4; body[6] = 0; body[7] = 0x50;
    body[8] = 0xf2; body[9] = 1;
    write16(body + 10, 0x11);
    B::OwnedSnapshot headerOnly = decoded(record, sizeof(record), body,
                                          B::BeaconFixedBodyBytes);
    assert(headerOnly.network.encryptionModes == 2);
}

static void test_unaligned_owned_inputs() {
    const uint8_t ssid[] = {'u', 0, 'a'};
    uint8_t recordStorage[B::Record4331Size + 1];
    uint8_t bodyStorage[B::MaximumBeaconBodyBytes + 1];
    uint8_t *record = recordStorage + 1;
    uint8_t *body = bodyStorage + 1;
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true, false);
    B::OwnedSnapshot snapshot = decoded(record, B::Record4331Size,
                                        body, bodySize);
    assert(snapshot.network.ssidLength == sizeof(ssid));
    assert(std::memcmp(snapshot.network.ssid, ssid, sizeof(ssid)) == 0);

    C::Fingerprint fp {};
    assert(C::fingerprint(record, B::Record4331Size, &fp));
    C::Registry registry;
    C::Ticket ticket;
    const uintptr_t thread = 1, wlc = 0x1000, cfg = 0x2000, source = 0x3000;
    const uint64_t epoch = 9;
    assert(registry.begin(thread, ticket));
    assert(registry.stage(ticket, epoch, wlc, cfg, source,
                          record, B::Record4331Size, snapshot));
    B::OwnedSnapshot out {};
    assert(registry.take(thread, epoch, wlc, cfg, source,
                         record, B::Record4331Size, &out));
    assert(sameSnapshot(out, snapshot));
}

struct Keys {
    uintptr_t thread = 1;
    uintptr_t wlc = 0x1000;
    uintptr_t cfg = 0x2000;
    uintptr_t source = 0x3000;
    uintptr_t target = 0x4000;
    uint64_t epoch = 9;
};

static void stageOne(C::Registry &registry, C::Ticket &ticket, const Keys &key,
                     const uint8_t *record, const B::OwnedSnapshot &snapshot) {
    assert(registry.begin(key.thread, ticket));
    assert(registry.stage(ticket, key.epoch, key.wlc, key.cfg, key.source,
                          record, B::Record4331Size, snapshot));
}

static void test_pending_stage_take_and_single_use() {
    const uint8_t ssid[] = {'b', 'c', 'm'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    const Keys key {};
    C::Registry registry;
    C::Ticket ticket;
    stageOne(registry, ticket, key, record, snapshot);

    B::OwnedSnapshot out = sentinelSnapshot();
    assert(registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));
    const B::OwnedSnapshot before = sentinelSnapshot();
    out = before;
    assert(!registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), &out));
    assert(sameSnapshot(out, before));
    assert(!registry.stage(ticket, key.epoch, key.wlc, key.cfg, key.source,
                           record, sizeof(record), snapshot));
}

static void test_take_mismatch_consumes_transaction() {
    const uint8_t ssid[] = {'m'};
    uint8_t record[B::Record4331Size], changed[B::Record4331Size];
    uint8_t body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    const Keys key {};

    for (int mismatch = 0; mismatch < 7; ++mismatch) {
        C::Registry registry;
        C::Ticket ticket;
        stageOne(registry, ticket, key, record, snapshot);
        B::OwnedSnapshot out = sentinelSnapshot();
        const B::OwnedSnapshot before = out;
        uintptr_t wlc = key.wlc, cfg = key.cfg, source = key.source;
        uint64_t epoch = key.epoch;
        const uint8_t *recordToUse = record;
        size_t recordSize = sizeof(record);
        std::memcpy(changed, record, sizeof(changed));
        switch (mismatch) {
        case 0: epoch++; break;
        case 1: wlc++; break;
        case 2: cfg++; break;
        case 3: source++; break;
        case 4: changed[B::SSIDOffset] ^= 1; recordToUse = changed; break;
        case 5: changed[B::Capability4331Offset] ^= 1; recordToUse = changed; break;
        case 6: recordSize--; break;
        }
        assert(!registry.take(key.thread, epoch, wlc, cfg, source, recordToUse,
                              recordSize, &out));
        assert(sameSnapshot(out, before));
        out = before;
        assert(!registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                              record, sizeof(record), &out));
        assert(sameSnapshot(out, before));
    }
}

static void test_mismatched_thread_and_wrong_registry_do_not_stage() {
    const uint8_t ssid[] = {'t'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    Keys key {};
    C::Registry first, second;
    C::Ticket ticket;
    stageOne(first, ticket, key, record, snapshot);
    assert(!second.stage(ticket, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), snapshot));
    B::OwnedSnapshot out = sentinelSnapshot();
    const B::OwnedSnapshot before = out;
    assert(!first.take(key.thread + 1, key.epoch, key.wlc, key.cfg, key.source,
                      record, sizeof(record), &out));
    assert(sameSnapshot(out, before));
    assert(first.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                      record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));
}

static void test_begin_reentry_invalidate_and_clear_pending() {
    const uint8_t ssid[] = {'r'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    Keys key {};
    C::Registry registry;
    C::Ticket first, nested;
    stageOne(registry, first, key, record, snapshot);
    assert(registry.begin(key.thread, nested));
    assert(!registry.stage(first, key.epoch, key.wlc, key.cfg, key.source,
                           record, sizeof(record), snapshot));
    B::OwnedSnapshot out = sentinelSnapshot();
    assert(registry.stage(nested, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    assert(registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    C::Ticket invalidated;
    assert(registry.begin(key.thread, invalidated));
    assert(registry.stage(invalidated, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    registry.invalidate(key.thread);
    assert(!registry.stage(invalidated, key.epoch, key.wlc, key.cfg, key.source,
                           record, sizeof(record), snapshot));
    assert(!registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), &out));

    C::Ticket otherThread;
    assert(registry.begin(key.thread + 1, otherThread));
    assert(registry.stage(otherThread, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    registry.clearPending();
    assert(!registry.take(key.thread + 1, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), &out));
    C::Ticket fresh;
    assert(registry.begin(key.thread + 1, fresh)); // Clearing never reuses nonce.
    assert(!registry.stage(otherThread, key.epoch, key.wlc, key.cfg, key.source,
                           record, sizeof(record), snapshot));
    assert(registry.stage(fresh, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
}

static void test_cancel_exact_ticket_does_not_clear_newer_or_committed_state() {
    const uint8_t ssid[] = {'k'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    const Keys key {};
    C::Registry registry;
    assert(registry.publish(5, key.wlc, key.cfg, key.target,
                            record, sizeof(record), snapshot));

    C::Ticket outer, nested;
    assert(registry.begin(key.thread, outer));
    assert(registry.stage(outer, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    assert(registry.begin(key.thread, nested)); // Replaces the same-thread token.
    registry.cancel(outer); // Stale outer ticket must not erase `nested`.
    assert(registry.stage(nested, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    B::OwnedSnapshot out {};
    assert(registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    C::Ticket cancelled, other;
    assert(registry.begin(key.thread, cancelled));
    assert(registry.begin(key.thread + 1, other));
    assert(registry.stage(other, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    registry.cancel(cancelled); // Clears only its exact slot.
    assert(!registry.stage(cancelled, key.epoch, key.wlc, key.cfg, key.source,
                           record, sizeof(record), snapshot));
    assert(!registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), &out));
    assert(registry.take(key.thread + 1, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), &out));

    // Canceling a pending capture never clears a committed identity snapshot.
    assert(registry.lookup(5, key.wlc, key.cfg, key.target,
                           record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    // Cancel also releases a reserved slot after a full table rejected a new
    // thread, allowing that thread to reserve later without evicting others.
    C::Registry full;
    C::Ticket reservations[C::PendingCapacity + 1];
    for (size_t i = 0; i < C::PendingCapacity; ++i)
        assert(full.begin(i + 1, reservations[i]));
    assert(!full.begin(C::PendingCapacity + 1, reservations[C::PendingCapacity]));
    full.cancel(reservations[3]);
    assert(full.begin(C::PendingCapacity + 1, reservations[C::PendingCapacity]));
    assert(!full.stage(reservations[3], key.epoch, key.wlc, key.cfg, key.source,
                       record, sizeof(record), snapshot));
}

static void test_capacity_rejects_without_poison_or_eviction() {
    const uint8_t ssid[] = {'c'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    C::Registry registry;
    C::Ticket tickets[C::PendingCapacity + 1];
    Keys key {};
    for (size_t i = 0; i < C::PendingCapacity; ++i) {
        key.thread = i + 1;
        assert(registry.begin(key.thread, tickets[i]));
        assert(registry.stage(tickets[i], key.epoch, key.wlc, key.cfg, key.source,
                              record, sizeof(record), snapshot));
    }
    key.thread = C::PendingCapacity + 1;
    assert(!registry.begin(key.thread, tickets[C::PendingCapacity]));
    assert(!C::TestAccess::poisoned(registry));

    B::OwnedSnapshot out {};
    key.thread = 1;
    assert(registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                         record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));
    key.thread = C::PendingCapacity + 1;
    assert(registry.begin(key.thread, tickets[C::PendingCapacity]));
    assert(registry.stage(tickets[C::PendingCapacity], key.epoch, key.wlc, key.cfg,
                          key.source, record, sizeof(record), snapshot));
}

static void test_nonce_overflow_permanently_poisons_pending() {
    const uint8_t ssid[] = {'n'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    Keys key {};
    C::Registry registry;
    C::Ticket last;
    C::TestAccess::setNextNonce(registry, std::numeric_limits<uint64_t>::max());
    assert(registry.begin(key.thread, last));
    assert(registry.stage(last, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));

    C::Ticket overflow;
    assert(!registry.begin(key.thread + 1, overflow));
    assert(C::TestAccess::poisoned(registry));
    assert(!registry.stage(last, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), snapshot));
    registry.clearPending();
    C::Ticket after;
    assert(!registry.begin(key.thread + 2, after));
    B::OwnedSnapshot out = sentinelSnapshot();
    const B::OwnedSnapshot before = out;
    assert(!registry.take(key.thread, key.epoch, key.wlc, key.cfg, key.source,
                          record, sizeof(record), &out));
    assert(sameSnapshot(out, before));
}

static void test_publish_lookup_identity_epoch_and_bodyless_only() {
    const uint8_t ssid[] = {'p', 0, 'q'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 0x11);
    const size_t bodySize = makeBody(body, 0x11, true);
    const B::OwnedSnapshot snapshot = decoded(record, sizeof(record), body, bodySize);
    C::Registry registry;
    const uintptr_t wlc = 0x1000, cfg = 0x2000, target = 0x4000;
    assert(registry.publish(10, wlc, cfg, target, record, sizeof(record), snapshot));

    B::OwnedSnapshot out = sentinelSnapshot();
    assert(registry.lookup(10, wlc, cfg, target, record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    const B::OwnedSnapshot before = sentinelSnapshot();
    const auto expectMiss = [&](uint64_t epoch, uintptr_t useWlc, uintptr_t useCfg,
                                uintptr_t useTarget, const uint8_t *useRecord,
                                size_t useSize) {
        out = before;
        assert(!registry.lookup(epoch, useWlc, useCfg, useTarget,
                                useRecord, useSize, &out));
        assert(sameSnapshot(out, before));
    };
    expectMiss(11, wlc, cfg, target, record, sizeof(record));
    expectMiss(10, wlc + 1, cfg, target, record, sizeof(record));
    expectMiss(10, wlc, cfg + 1, target, record, sizeof(record));
    expectMiss(10, wlc, cfg, target + 1, record, sizeof(record));
    expectMiss(10, wlc, cfg, target, record, sizeof(record) - 1);

    // A later body defeats only the fallback lookup; it cannot be treated as
    // the same bodyless record.
    write64(record + B::IEPointerOffset, 0x1234);
    expectMiss(10, wlc, cfg, target, record, sizeof(record));
    write64(record + B::IEPointerOffset, 0);
    write16(record + B::IELengthOffset, 1);
    expectMiss(10, wlc, cfg, target, record, sizeof(record));
    write16(record + B::IELengthOffset, 0);

    // DTIM and unrelated scan metadata are intentionally outside the key.
    record[0x60] = 0xff;
    record[0x30] = 0x71;
    assert(registry.lookup(10, wlc, cfg, target, record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    write16(record + B::Capability4331Offset, 0x11 | 0x400 | 0x20);
    assert(registry.lookup(10, wlc, cfg, target, record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));
    write16(record + B::Capability4331Offset, 0x11);

    uint8_t changed[B::Record4331Size];
    std::memcpy(changed, record, sizeof(changed));
    changed[B::SSIDOffset] ^= 1;
    expectMiss(10, wlc, cfg, target, changed, sizeof(changed));
    changed[B::SSIDOffset] = record[B::SSIDOffset];
    changed[B::Capability4331Offset] ^= 1;
    expectMiss(10, wlc, cfg, target, changed, sizeof(changed));
    changed[B::Capability4331Offset] = record[B::Capability4331Offset];
    changed[0] ^= 2;
    expectMiss(10, wlc, cfg, target, changed, sizeof(changed));

    // Invalid publication leaves the prior committed value intact.
    B::OwnedSnapshot wrong = snapshot;
    wrong.network.ssid[0] ^= 1;
    assert(!registry.publish(11, wlc, cfg, target + 1, record, sizeof(record), wrong));
    assert(registry.lookup(10, wlc, cfg, target, record, sizeof(record), &out));
    assert(sameSnapshot(out, snapshot));

    // A valid new generation replaces the one committed slot.
    assert(registry.publish(11, wlc, cfg, target, record, sizeof(record), snapshot));
    expectMiss(10, wlc, cfg, target, record, sizeof(record));
    assert(registry.lookup(11, wlc, cfg, target, record, sizeof(record), &out));
}

static void test_unknown_assurance_is_stored_and_returned() {
    const uint8_t ssid[] = {'u'};
    uint8_t record[B::Record4331Size], body[B::MaximumBeaconBodyBytes];
    initRecord(record, ssid, sizeof(ssid), 1);
    const size_t bodySize = makeBody(body, 1, false, false);
    const B::OwnedSnapshot unknown = decoded(record, sizeof(record), body, bodySize);
    assert(unknown.networkAssurance == A::State::Unknown);
    C::Registry registry;
    assert(registry.publish(4, 0x1000, 0x2000, 0x4000,
                            record, sizeof(record), unknown));
    B::OwnedSnapshot out {};
    assert(registry.lookup(4, 0x1000, 0x2000, 0x4000,
                           record, sizeof(record), &out));
    assert(sameSnapshot(out, unknown));
}

int main() {
    test_fingerprint_fields_and_output_unchanged();
    test_decode_produced_full_body_without_mutation();
    test_decode_produced_rejects_invalid_shapes();
    test_pending_stage_take_and_single_use();
    test_take_mismatch_consumes_transaction();
    test_mismatched_thread_and_wrong_registry_do_not_stage();
    test_begin_reentry_invalidate_and_clear_pending();
    test_cancel_exact_ticket_does_not_clear_newer_or_committed_state();
    test_unaligned_owned_inputs();
    test_capacity_rejects_without_poison_or_eviction();
    test_nonce_overflow_permanently_poisons_pending();
    test_publish_lookup_identity_epoch_and_bodyless_only();
    test_unknown_assurance_is_stored_and_returned();
}
'''


class BSSCaptureTests(unittest.TestCase):
    def test_owned_parser_snapshot_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "test.cpp"
            binary = Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(
                ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                check=True, capture_output=True, timeout=45,
            )
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=20)


if __name__ == "__main__":
    unittest.main()
