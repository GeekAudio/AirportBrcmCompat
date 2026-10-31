"""Host regression coverage for the audited native SET10 request layouts."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "scan_single_bridge.hpp"
#include <assert.h>
#include <errno.h>
#include <initializer_list>
#include <string.h>

namespace S = LegacyWiFi::ScanSingleBridge;
namespace M = LegacyWiFi::ScanMultipleBridge;

static void put16(uint8_t *p, uint16_t value) { memcpy(p, &value, sizeof(value)); }
static void put32(uint8_t *p, uint32_t value) { memcpy(p, &value, sizeof(value)); }
static uint16_t get16(const uint8_t *p) { uint16_t value; memcpy(&value, p, sizeof(value)); return value; }
static uint32_t get32(const uint8_t *p) { uint32_t value; memcpy(&value, p, sizeof(value)); return value; }

static void init(uint8_t *p, const S::NativeLayout &layout, uint32_t channels) {
    memset(p, 0, layout.size);
    put32(p + S::VersionOffset, 1);
    put32(p + S::APModeOffset, 2);
    const uint8_t bssid[] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    memcpy(p + S::BSSIDOffset, bssid, sizeof(bssid));
    put32(p + S::SSIDLengthOffset, 3);
    memcpy(p + S::SSIDBytesOffset, "abc", 3);
    put32(p + S::ScanTypeOffset, 1);
    put32(p + S::PHYModeOffset, 3);
    put16(p + S::DwellTimeOffset, 1200);
    put32(p + S::RestTimeOffset, 27);
    put32(p + S::ChannelCountOffset, channels);
    for (uint32_t i = 0; i < channels; ++i) {
        uint8_t *channel = p + S::ChannelsOffset + size_t(i) * S::ChannelStride;
        put32(channel, 1);
        put32(channel + 4, 36 + i);
        put32(channel + 8, 0x100 + i);
    }
}

static S::NativeLayout layoutFor(size_t size) {
    S::NativeLayout layout{};
    assert(S::nativeLayoutForSize(size, layout));
    return layout;
}

static void profileTable() {
    struct Expected {
        size_t size;
        S::Profile profile;
        size_t capacity, end, flags, count, array, arrayEnd;
    } expected[] = {
        {S::Monterey12Size, S::Profile::Monterey12, 128, 0x648, 0x648, 0x654, 0x658, 0x850},
        {S::Ventura13Size, S::Profile::Ventura13, 400, 0x1308, 0x1308, 0x1314, 0x1318, 0x1510},
        {S::Sonoma14Size, S::Profile::Sonoma14, 400, 0x1308, 0x1308, 0x1314, 0x1318, 0x1510},
        {S::Sequoia15Tahoe26Size, S::Profile::Sequoia15Tahoe26, 400, 0x1308, 0x1308, 0x1314, 0x1318, 0x1510},
    };
    for (const auto &item : expected) {
        S::NativeLayout layout{};
        assert(S::nativeLayoutForSize(item.size, layout));
        assert(layout.profile == item.profile && layout.size == item.size);
        assert(layout.channelCapacity == item.capacity && layout.channelsEnd == item.end);
        assert(layout.flagsOffset == item.flags && layout.ssidCountOffset == item.count);
        assert(layout.ssidArrayOffset == item.array && layout.ssidArrayEnd == item.arrayEnd);
    }
    S::NativeLayout layout{};
    for (size_t unsupported : {size_t(0), size_t(0x954), size_t(0x1551), size_t(0x1591), size_t(0x1599)})
        assert(!S::nativeLayoutForSize(unsupported, layout));
    assert(S::ElCapSize == 0x954);
}

static void directSSIDProjection() {
    const S::NativeLayout layout = layoutFor(S::Sonoma14Size);
    uint8_t native[S::Sonoma14Size], old[S::ElCapSize];
    init(native, layout, 4);
    assert(!S::validateNativeShape(native, sizeof(native), &layout).error);
    memset(old, 0x6d, sizeof(old));
    const auto result = S::convertToElCap(native, sizeof(native), old, sizeof(old));
    assert(!result.error && result.field == 0);
    assert(get32(old + S::VersionOffset) == 1 && get32(old + S::APModeOffset) == 2);
    assert(!memcmp(old + S::BSSIDOffset, native + S::BSSIDOffset, 6));
    assert(get32(old + S::SSIDLengthOffset) == 3);
    assert(!memcmp(old + S::SSIDBytesOffset, "abc", 3));
    assert(get32(old + S::ScanTypeOffset) == 1 && get32(old + S::PHYModeOffset) == 3);
    assert(get16(old + S::DwellTimeOffset) == 1200);
    assert(old[S::DwellTimeOffset + 2] == 0 && old[S::DwellTimeOffset + 3] == 0);
    assert(get32(old + S::RestTimeOffset) == 27 && get32(old + S::ChannelCountOffset) == 4);
    assert(!memcmp(old + S::ChannelsOffset, native + S::ChannelsOffset,
                   4 * S::ChannelStride));
    for (size_t i = S::ChannelsOffset + 4 * S::ChannelStride; i < sizeof(old); ++i)
        assert(old[i] == 0);
    assert(get32(native + S::SSIDLengthOffset) == 3); // input remains untouched
}

static void extendedSSIDProjection() {
    const S::NativeLayout layout = layoutFor(S::Sequoia15Tahoe26Size);
    uint8_t native[S::Sequoia15Tahoe26Size], old[S::ElCapSize], multiple[M::NativeSize];
    init(native, layout, 1);
    put32(native + S::SSIDLengthOffset, 0);
    memset(native + S::SSIDBytesOffset, 0, S::SSIDCapacity);
    put32(native + layout.ssidCountOffset, 2);
    const size_t first = layout.ssidArrayOffset;
    const size_t second = first + S::NativeSSIDStride;
    put32(native + first + S::NativeSSIDTypeOffset, 1);
    put32(native + first + S::NativeSSIDLengthOffset, 3);
    memcpy(native + first + S::NativeSSIDBytesOffset, "one", 3);
    put32(native + second + S::NativeSSIDTypeOffset, 1);
    put32(native + second + S::NativeSSIDLengthOffset, 4);
    memcpy(native + second + S::NativeSSIDBytesOffset, "two2", 4);
    assert(!S::validateNativeShape(native, sizeof(native), &layout).error);
    assert(!S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple)).error);
    assert(M::validateNativeShape(multiple, sizeof(multiple)).error == 0);
    assert(get32(multiple + M::NativeSSIDCount) == 2);
    assert(get32(multiple + M::NativeSSIDArray + M::SSIDLengthOffset) == 3);
    assert(!memcmp(multiple + M::NativeSSIDArray + M::SSIDBytesOffset, "one", 3));
    const size_t multipleSecond = M::NativeSSIDArray + M::SSIDStride;
    assert(get32(multiple + multipleSecond + M::SSIDLengthOffset) == 4);
    assert(!memcmp(multiple + multipleSecond + M::SSIDBytesOffset, "two2", 4));
    memset(old, 0xcc, sizeof(old));
    const auto tooMany = S::convertToElCap(native, sizeof(native), old, sizeof(old));
    assert(tooMany.error == EOPNOTSUPP && tooMany.field == layout.ssidCountOffset);
    for (uint8_t byte : old) assert(byte == 0xcc); // SET10 represents only one SSID.

    // A one-element native SSID list can be represented in the old direct
    // SSID field without changing the other common prefix values.
    put32(native + layout.ssidCountOffset, 1);
    memset(native + second, 0, S::NativeSSIDStride);
    assert(!S::convertToElCap(native, sizeof(native), old, sizeof(old)).error);
    assert(get32(old + S::SSIDLengthOffset) == 3);
    assert(!memcmp(old + S::SSIDBytesOffset, "one", 3));
}

static void normalizationAndChannelBounds() {
    const S::NativeLayout layout = layoutFor(S::Ventura13Size);
    uint8_t native[S::Ventura13Size];
    uint8_t old[S::ElCapSize];
    uint8_t multiple[M::NativeSize];
    init(native, layout, 129);
    const auto valid = S::validateNativeShape(native, sizeof(native), &layout);
    assert(!valid.error);
    memset(old, 0xa5, sizeof(old));
    const auto tooManyForOld = S::convertToElCap(native, sizeof(native), old, sizeof(old));
    assert(tooManyForOld.error == EOPNOTSUPP && tooManyForOld.field == S::ChannelCountOffset);
    for (uint8_t byte : old) assert(byte == 0xa5); // rejected without partial write

    memset(multiple, 0xb4, sizeof(multiple));
    assert(!S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple)).error);
    assert(M::validateNativeShape(multiple, sizeof(multiple)).error == 0);
    assert(get32(multiple) == 1 && get32(multiple + 4) == 2);
    assert(get32(multiple + M::NativeSSIDCount) == 1);
    assert(get32(multiple + M::NativeSSIDArray) == 1);
    assert(get32(multiple + M::NativeSSIDArray + M::SSIDLengthOffset) == 3);
    assert(!memcmp(multiple + M::NativeSSIDArray + M::SSIDBytesOffset, "abc", 3));
    assert(get32(multiple + M::NativeBSSIDCount) == 1);
    assert(!memcmp(multiple + M::NativeBSSIDArray, native + S::BSSIDOffset, 6));
    assert(get32(multiple + M::NativeScanType) == 1 && get32(multiple + M::NativePhyMode) == 3);
    assert(get32(multiple + M::NativeDwellTime) == 1200);
    assert(get32(multiple + M::NativeRestTime) == 27);
    assert(get32(multiple + M::NativeChannelCount) == 129);
    assert(!memcmp(multiple + M::NativeChannels, native + S::ChannelsOffset,
                   129 * S::ChannelStride));

    // The modern producer's 400-entry table can be normalized in full; the
    // planner, not this schema converter, decides how to split it into jobs.
    init(native, layout, 400);
    assert(!S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple)).error);
    assert(M::validateNativeShape(multiple, sizeof(multiple)).error == 0);
    assert(get32(multiple + M::NativeChannelCount) == 400);

    const S::NativeLayout oldLayout = layoutFor(S::Monterey12Size);
    uint8_t oldNative[S::Monterey12Size];
    init(oldNative, oldLayout, 128);
    assert(!S::convertToElCap(oldNative, sizeof(oldNative), old, sizeof(old)).error);
    init(oldNative, oldLayout, 129);
    assert(S::validateNativeShape(oldNative, sizeof(oldNative)).error == EINVAL);
}

static void rejectsUnknownOrMalformedFields() {
    const S::NativeLayout layout = layoutFor(S::Sonoma14Size);
    uint8_t native[S::Sonoma14Size], old[S::ElCapSize], multiple[M::NativeSize];
    auto check = [&](int error, size_t field) {
        memset(old, 0x5a, sizeof(old));
        uint8_t before[sizeof(old)]; memcpy(before, old, sizeof(old));
        memset(multiple, 0x6b, sizeof(multiple));
        uint8_t multiBefore[sizeof(multiple)]; memcpy(multiBefore, multiple, sizeof(multiple));
        const auto projected = S::convertToElCap(native, sizeof(native), old, sizeof(old));
        const auto normalized = S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple));
        assert(projected.error == error && projected.field == field);
        assert(normalized.error == error && normalized.field == field);
        assert(!memcmp(old, before, sizeof(old)));
        assert(!memcmp(multiple, multiBefore, sizeof(multiple)));
    };

    init(native, layout, 1); put32(native + S::VersionOffset, 2); check(EINVAL, S::VersionOffset);
    init(native, layout, 1); put32(native + S::APModeOffset, 0); check(EINVAL, S::APModeOffset);
    init(native, layout, 1); put32(native + S::SSIDLengthOffset, 33); check(EINVAL, S::SSIDLengthOffset);
    init(native, layout, 1); native[S::BSSIDOffset + 6] = 1; check(EINVAL, S::BSSIDOffset + 6);
    init(native, layout, 1); native[S::SSIDBytesOffset + 3] = 1; check(EINVAL, S::SSIDBytesOffset + 3);
    init(native, layout, 1); put32(native + S::ScanTypeOffset, 4); check(EINVAL, S::ScanTypeOffset);
    init(native, layout, 1); native[S::DwellTimeOffset + 2] = 1; check(EINVAL, S::DwellTimeOffset + 2);
    init(native, layout, 1); native[S::ChannelsOffset + S::ChannelStride] = 1;
    check(EINVAL, S::ChannelsOffset + S::ChannelStride);
    init(native, layout, 1); native[layout.flagsOffset] = 1; check(EOPNOTSUPP, layout.flagsOffset);
    init(native, layout, 1); put32(native + layout.ssidCountOffset, S::MaxNativeSSIDList + 1);
    check(EINVAL, layout.ssidCountOffset);
    init(native, layout, 1); put32(native + layout.ssidCountOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDTypeOffset, 0);
    check(EINVAL, layout.ssidArrayOffset + S::NativeSSIDTypeOffset);
    init(native, layout, 1); put32(native + layout.ssidCountOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDTypeOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDLengthOffset, 33);
    check(EINVAL, layout.ssidArrayOffset + S::NativeSSIDLengthOffset);
    init(native, layout, 1); put32(native + layout.ssidCountOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDTypeOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDLengthOffset, 3);
    native[layout.ssidArrayOffset + S::NativeSSIDBytesOffset + 3] = 1;
    check(EINVAL, layout.ssidArrayOffset + S::NativeSSIDBytesOffset + 3);
    init(native, layout, 1); native[layout.ssidArrayEnd] = 1;
    check(EOPNOTSUPP, layout.ssidArrayEnd);
    init(native, layout, 1); put32(native + S::SSIDLengthOffset, 3);
    put32(native + layout.ssidCountOffset, 1);
    put32(native + layout.ssidArrayOffset + S::NativeSSIDTypeOffset, 1);
    check(EOPNOTSUPP, S::SSIDLengthOffset);
    init(native, layout, 401); check(EINVAL, S::ChannelCountOffset);
}

static void invalidBuffersAndDirectNoSSIDNormalization() {
    const S::NativeLayout layout = layoutFor(S::Monterey12Size);
    uint8_t native[S::Monterey12Size], old[S::ElCapSize], multiple[M::NativeSize];
    init(native, layout, 0);
    put32(native + S::SSIDLengthOffset, 0);
    memset(native + S::SSIDBytesOffset, 0, S::SSIDCapacity);
    assert(!S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple)).error);
    assert(M::validateNativeShape(multiple, sizeof(multiple)).error == 0);
    assert(get32(multiple + M::NativeSSIDCount) == 0);
    assert(get32(multiple + M::NativeBSSIDCount) == 1);

    assert(S::convertToElCap(nullptr, sizeof(native), old, sizeof(old)).error == EINVAL);
    assert(S::convertToElCap(native, sizeof(native), nullptr, sizeof(old)).error == EINVAL);
    assert(S::convertToElCap(native, sizeof(native) - 1, old, sizeof(old)).error == EINVAL);
    assert(S::convertToElCap(native, sizeof(native), old, sizeof(old) - 1).error == EINVAL);
    assert(S::convertToElCap(native, sizeof(native), native, sizeof(old)).error == EINVAL);
    assert(S::normalizeToScanMultiple(native, sizeof(native), nullptr, sizeof(multiple)).error == EINVAL);
    assert(S::normalizeToScanMultiple(native, sizeof(native), multiple, sizeof(multiple) - 1).error == EINVAL);
    assert(S::normalizeToScanMultiple(native, sizeof(native), native, sizeof(multiple)).error == EINVAL);
    S::NativeLayout mismatch = layout; mismatch.size++;
    assert(S::validateNativeShape(native, sizeof(native), &mismatch).error == EINVAL);
}

int main() {
    profileTable();
    directSSIDProjection();
    extendedSSIDProjection();
    normalizationAndChannelBounds();
    rejectsUnknownOrMalformedFields();
    invalidBuffersAndDirectNoSSIDNormalization();
}
'''


class LegacyScanSingleBridgeTests(unittest.TestCase):
    def test_known_profiles_project_and_normalize_without_dropping_data(self):
        with tempfile.TemporaryDirectory(prefix="legacy-scan-single-") as folder:
            source = pathlib.Path(folder) / "test.cpp"
            binary = pathlib.Path(folder) / "test"
            source.write_text(HARNESS)
            build = subprocess.run(
                [
                    "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                    "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                    "-I", str(PROJECT / "src/scan_kernel"),
                    "-I", str(PROJECT / "src/legacy_wifi_compat"),
                    str(source), "-o", str(binary),
                ],
                text=True, capture_output=True, timeout=30,
            )
            self.assertEqual(build.returncode, 0, build.stderr)
            run = subprocess.run([str(binary)], text=True, capture_output=True, timeout=5)
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
