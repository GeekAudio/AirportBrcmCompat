"""Offline checks for the pinned legacy native-kernel-event contract."""
import pathlib
import subprocess
import tempfile
import unittest


PROJECT = pathlib.Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/event_router.hpp"
#include "legacy_wifi_compat/event_binding_state.hpp"
#include <assert.h>
#include <atomic>
#include <stdint.h>
#include <string.h>
#include <thread>
#include <utility>
#include <vector>

namespace E = LegacyWiFi::EventContracts;

static void bindingCreationRetirementRace() {
    using E::BindingState;
    for (unsigned iteration = 0; iteration < 1000; ++iteration) {
        std::atomic<BindingState> state{BindingState::Creating};
        std::atomic<bool> terminationRecorded{false};
        std::atomic<bool> creatorMayFinish{false};

        std::thread creator([&] {
            while (!creatorMayFinish.load(std::memory_order_acquire))
                std::this_thread::yield();
            const auto current = state.load(std::memory_order_acquire);
            state.store(E::bindingCreationFinished(current, false),
                        std::memory_order_release);
        });
        std::thread termination([&] {
            const auto current = state.load(std::memory_order_acquire);
            assert(current == BindingState::Creating);
            state.store(E::bindingTerminationRequested(current),
                        std::memory_order_release);
            terminationRecorded.store(true, std::memory_order_release);
        });
        std::thread contender([&] {
            while (!terminationRecorded.load(std::memory_order_acquire))
                std::this_thread::yield();
            const auto current = state.load(std::memory_order_acquire);
            assert(current == BindingState::AbortRequested);
            // A competing bind/cleanup worker cannot reclaim the slot while
            // the creator still owns notifier publication and retained refs.
            assert(!E::bindingSlotAvailable(current));
        });
        termination.join();
        contender.join();
        creatorMayFinish.store(true, std::memory_order_release);
        creator.join();
        const auto finished = state.load(std::memory_order_acquire);
        assert(finished == BindingState::Retired);
        assert(!E::bindingSlotAvailable(finished));
    }
}

static void put32(uint8_t *p, uint32_t value) {
    p[0] = static_cast<uint8_t>(value);
    p[1] = static_cast<uint8_t>(value >> 8);
    p[2] = static_cast<uint8_t>(value >> 16);
    p[3] = static_cast<uint8_t>(value >> 24);
}
static uint32_t get32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}
static void put64(uint8_t *p, uint64_t value) {
    put32(p, static_cast<uint32_t>(value));
    put32(p + 4, static_cast<uint32_t>(value >> 32));
}
static void putRel32(uint8_t *bytes, size_t instructionOffset,
                     uintptr_t target) {
    const uintptr_t origin = reinterpret_cast<uintptr_t>(bytes) + instructionOffset + 5;
    const int64_t delta = static_cast<int64_t>(target) - static_cast<int64_t>(origin);
    assert(delta >= INT32_MIN && delta <= INT32_MAX);
    put32(bytes + instructionOffset + 1, static_cast<uint32_t>(static_cast<int32_t>(delta)));
}
static void initImage(uint8_t *bytes, size_t size, const uint8_t uuid[16]) {
    memset(bytes, 0xcc, size);
    put32(bytes, 0xfeedfacf);
    put32(bytes + 4, 0x01000007); // CPU_TYPE_X86_64
    put32(bytes + 8, 3);          // CPU_SUBTYPE_X86_64_ALL
    put32(bytes + 12, 0x0b);      // MH_KEXT_BUNDLE
    put32(bytes + 16, 2);   // ncmds
    put32(bytes + 20, 176); // sizeofcmds: one segment, one section, one UUID
    uint8_t *segment = bytes + 32;
    put32(segment, 0x19); put32(segment + 4, 152);
    memset(segment + 8, 0, 16);
    memcpy(segment + 8, "__TEXT", 6);
    put64(segment + 24, 0); put64(segment + 32, size); put64(segment + 40, 0);
    put64(segment + 48, size); put32(segment + 56, 5); put32(segment + 60, 5);
    put32(segment + 64, 1); // nsects
    uint8_t *text = segment + 72;
    memset(text, 0, 80);
    memcpy(text, "__text", 6); memcpy(text + 16, "__TEXT", 6);
    put64(text + 32, 0x1000); put64(text + 40, size - 0x1000);
    put32(text + 48, 0x1000); put32(text + 64, 0x80000400);
    uint8_t *uuidCommand = segment + 152;
    put32(uuidCommand, 0x1b); put32(uuidCommand + 4, 24);
    memcpy(uuidCommand + 8, uuid, 16);
}
static void rebaseTextSegment(uint8_t *bytes) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(bytes);
    put64(bytes + 32 + 24, base);
    put64(bytes + 32 + 72 + 32, base + 0x1000);
}

static const uint8_t ProviderUUID[16] = {
    0xb6,0xa4,0x3e,0xdc,0x47,0xe9,0x3d,0xb8,0x98,0x87,0x81,0x2d,0x1c,0x77,0xf3,0x8c
};
static const uint8_t UUID4331[16] = {
    0x59,0xc1,0xf2,0xa3,0xd3,0xb8,0x3c,0x3e,0x8d,0x7d,0x3e,0x58,0xcb,0xd5,0x45,0x00
};
static const uint8_t UUID43224[16] = {
    0x6f,0x07,0x4d,0x2e,0xe7,0xe8,0x32,0x7b,0xac,0x63,0xf5,0x04,0xb7,0x36,0x7b,0xa4
};

static E::ProviderSymbols providerSymbols(const uint8_t *image) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(image);
    return {base + 0x5822e, base + 0x58358, base + 0x5d993,
            base + 0x61d9e, base + 0x744d4};
}
static E::DriverSymbols driverSymbols(const uint8_t *image, E::DriverKind kind) {
    const uintptr_t base = reinterpret_cast<uintptr_t>(image);
    return kind == E::DriverKind::Broadcom4331
        ? E::DriverSymbols{base + 0xd350, base + 0xd202}
        : E::DriverSymbols{base + 0x95da, base + 0x94f6};
}

static void initProvider(uint8_t *image) {
    initImage(image, 0x76000, ProviderUUID);
    static const uint8_t postMessageEntry[] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0x48,
        0x83,0xec,0x40,0x41,0x89,0xf7,0x49,0x89,0xfe,0x48,0x89,0x55,
        0xc8,0x48,0x89,0x4d,0xc0
    };
    memcpy(image + 0x58358, postMessageEntry, sizeof(postMessageEntry));
    static const uint8_t messageDispatcher[] = {
        0x41,0x83,0xff,0x47,0x7f,0x50,0x41,0x83,0xff,0x1f,0x0f,0x8f,
        0x91,0x00,0x00,0x00,0x41,0x83,0xff,0x08,0x0f,0x8f,0x05,0x01,
        0x00,0x00,0x41,0x83,0xff,0x02,0x0f,0x85,0x55,0x01,0x00,0x00
    };
    memcpy(image + 0x58375, messageDispatcher, sizeof(messageDispatcher));
    static const uint8_t code2EmptyPayloadRoute[] = {
        0x48,0x85,0xc9,0x0f,0x84,0x67,0x03,0x00,0x00
    };
    memcpy(image + 0x58399, code2EmptyPayloadRoute,
           sizeof(code2EmptyPayloadRoute));
    static const uint8_t code4Unwrap[] = {
        0x41,0x83,0xff,0x04,0x0f,0x85,0x11,0x02,0x00,0x00,0x49,0x8b,
        0xbe,0xb8,0x02,0x00,0x00,0x48,0x85,0xff,0x74,0x0b,0x48,0x89,
        0xd6,0x48,0x89,0xca,0xe8,0x41,0x2d,0x01,0x00,0x48,0x8d,0x55,
        0xc8,0x48,0x8d,0x4d,0xc0,0xbe,0x04,0x00,0x00,0x00,0xe8,0xc9,
        0xfd,0xff,0xff,0x85,0xc0,0x0f,0x84,0xe0,0x01,0x00,0x00,0x48,
        0x8d,0x55,0xc8,0x48,0x8d,0x4d,0xc0,0xbe,0x0d,0x00,0x00,0x00,
        0xe8,0xaf,0xfd,0xff,0xff,0x85,0xc0,0x0f,0x84,0xc6,0x01,0x00,
        0x00,0x48,0x8d,0x55,0xc8,0x48,0x8d,0x4d,0xc0,0xbe,0x0e,0x00,
        0x00,0x00,0xe9,0x44,0x01,0x00,0x00
    };
    memcpy(image + 0x584ee, code4Unwrap, sizeof(code4Unwrap));
    // Code 20 takes a separate dispatcher path from code 3: code 20 fails the
    // code-9 and code-14 comparisons before reaching the shared route selector.
    static const uint8_t code20Not9Dispatch[] = {
        0x41,0x83,0xff,0x09,0x0f,0x85,0xb7,0x00,0x00,0x00
    };
    memcpy(image + 0x58494, code20Not9Dispatch,
           sizeof(code20Not9Dispatch));
    static const uint8_t code20Not14Route[] = {
        0x41,0x83,0xff,0x0e,0x0f,0x85,0xaa,0x01,0x00,0x00
    };
    memcpy(image + 0x58555, code20Not14Route,
           sizeof(code20Not14Route));
    static const uint8_t type14Result[] = {
        0xe8,0x4c,0xfc,0xff,0xff,0x3d,0xf0,0x02,0x00,0xe0,0x75,0x64
    };
    memcpy(image + 0x58699, type14Result, sizeof(type14Result));
    static const uint8_t setDataPointerAndLengthForMessageType[] = {
        0x55,0x48,0x89,0xe5,0x4c,0x8b,0x0a,0xb8,0xf0,0x02,0x00,0xe0,
        0x4d,0x85,0xc9,0x74,0x42,0x4c,0x8b,0x01,0xb8,0xf0,0x02,0x00,
        0xe0,0x31,0xff,0x49,0x83,0xf8,0x08,0x72,0x32,0x4c,0x8d,0x57,
        0x08,0x41,0x39,0x34,0x39,0x75,0x19,0x4f,0x8d,0x1c,0x11,0x4c,
        0x89,0x1a,0x42,0x8b,0x7c,0x0f,0x04,0x48,0x89,0x39,0x31,0xc0,
        0x49,0x89,0xf8,0x4d,0x89,0xd9,0xeb,0x05,0x42,0x8b,0x7c,0x0f,
        0x04,0x89,0xff,0x4c,0x01,0xd7,0x4c,0x39,0xc7,0x72,0xce,0x5d,
        0xc3
    };
    memcpy(image + 0x582ea, setDataPointerAndLengthForMessageType,
           sizeof(setDataPointerAndLengthForMessageType));
    static const uint8_t routeSelect[] = {0x49,0x83,0xbe,0x48,0x01,0,0,0,0x74,0x47};
    memcpy(image + 0x58709, routeSelect, sizeof(routeSelect));
    static const uint8_t fallback[] = {
        0x4c,0x89,0xf7,0xe8,0,0,0,0,0x4c,0x8b,0x65,0xc8,0x48,0x8b,0x5d,0xc0,
        0x48,0x89,0xc7,0x44,0x89,0xfe,0x4c,0x89,0xe2,0x48,0x89,0xd9,0xe8,0,0,0,0
    };
    memcpy(image + 0x5875a, fallback, sizeof(fallback));
    putRel32(image, 0x5875d, reinterpret_cast<uintptr_t>(image) + 0x5822e);
    putRel32(image, 0x58776, reinterpret_cast<uintptr_t>(image) + 0x5d993);
    static const uint8_t scanCacheUpdated[] = {
        0x49,0x8b,0x7c,0x24,0x58,0xbe,0x0f,0,0,0,0x31,0xd2,0x31,0xc9,0xe8,0,0,0,0
    };
    memcpy(image + 0x61fbc, scanCacheUpdated, sizeof(scanCacheUpdated));
    putRel32(image, 0x61fca, reinterpret_cast<uintptr_t>(image) + 0x58358);
    static const uint8_t sender[] = {
        0xc7,0x45,0xa0,0x01,0,0,0,0xc7,0x45,0xa4,0x06,0,0,0,
        0xc7,0x45,0xa8,0x01,0,0,0,0x89,0x75,0xac,0xc7,0x45,0xb0,0x10,0,0,0,
        0x48,0x89,0x7d,0xb8,0x31,0xc0,0x48,0x85,0xc9,0x74,0x0d,0x48,0x89,0x55,
        0xc8,0xc7,0x45,0xd0,0,0,0,0,0x89,0xc8,0x89,0x45,0xc0,0x48,0x8d,0x7d,
        0xa0,0xe8,0,0,0,0
    };
    static const uint8_t bsdHelperPrelude[] = {
        0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x60,0x48,0x85,0xc9,0x74,0x15,
        0x83,0xfe,0x3a,0x74,0x58,0x48,0x85,0xd2,0x74,0x53,0x48,0x81,0xf9,
        0xf0,0x07,0x00,0x00,0x76,0x07,0xeb,0x48,0x83,0xfe,0x3a,0x74,0x43
    };
    memcpy(image + 0x5d993, bsdHelperPrelude, sizeof(bsdHelperPrelude));
    memcpy(image + 0x5d9ba, sender, sizeof(sender));
    putRel32(image, 0x5d9f8, reinterpret_cast<uintptr_t>(image) + 0x744d4);
}

static void initDriver(uint8_t *image, E::DriverKind kind,
                       const E::ProviderSymbols &provider) {
    const bool is4331 = kind == E::DriverKind::Broadcom4331;
    initImage(image, 0x10000, is4331 ? UUID4331 : UUID43224);
    if (is4331) {
        static const uint8_t bytes[] = {
            0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0x83,0xfe,0x10,0x74,0x3e,
            0x48,0x8b,0x83,0x68,0x04,0,0,0x48,0x8b,0xb0,0x58,0x08,0,0,
            0x48,0x89,0xdf,0xe8,0,0,0,0,0x48,0x8b,0x03,0x48,0x89,0xdf,0xff,
            0x90,0x88,0x0c,0,0,0x48,0x85,0xc0,0x74,0x17,0xbe,0x0a,0,0,0,
            0x31,0xd2,0x31,0xc9,0x48,0x89,0xc7,0x48,0x83,0xc4,0x08,0x5b,0x5d,
            0xe9,0,0,0,0
        };
        memcpy(image + 0xd350, bytes, sizeof(bytes));
        putRel32(image, 0xd36f, reinterpret_cast<uintptr_t>(image) + 0xd202);
        putRel32(image, 0xd397, provider.postMessage);
    } else {
        static const uint8_t bytes[] = {
            0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0x48,0x8b,0xb3,0x18,0x04,
            0,0,0x48,0x81,0xc6,0xc8,0x21,0,0,0xe8,0,0,0,0,0x48,0x8b,0x03,0x48,
            0x89,0xdf,0xff,0x90,0x88,0x0c,0,0,0x48,0x85,0xc0,0x74,0x17,0xbe,0x0a,
            0,0,0,0x31,0xd2,0x31,0xc9,0x48,0x89,0xc7,0x48,0x83,0xc4,0x08,0x5b,
            0x5d,0xe9,0,0,0,0
        };
        memcpy(image + 0x95da, bytes, sizeof(bytes));
        putRel32(image, 0x95f1, reinterpret_cast<uintptr_t>(image) + 0x94f6);
        putRel32(image, 0x9619, provider.postMessage);
    }
}

static void imageAdmission() {
    std::vector<uint8_t> arena(0x90000);
    uint8_t *providerBytes = arena.data();
    uint8_t *driverBytes = arena.data() + 0x80000;
    initProvider(providerBytes);
    E::LoadedImage provider{providerBytes, 0x76000};
    const auto ps = providerSymbols(providerBytes);
    assert(E::verifyProvider(provider, ps));
    // These loaded provider bytes cover code 3's default route, code 20's
    // separate conditional route, and the code-4 type order plus shared TLV
    // parser. Mutations to dispatch targets, the +8 pointer, length field
    // offset, or any type selector must fail closed.
    for (const auto mutation : {std::pair<size_t,uint8_t>{0x5830e,0x09},
                                std::pair<size_t,uint8_t>{0x58320,0x05},
                                std::pair<size_t,uint8_t>{0x58393,0x86},
                                std::pair<size_t,uint8_t>{0x5839e,0x66},
                                std::pair<size_t,uint8_t>{0x58518,0x0d},
                                std::pair<size_t,uint8_t>{0x58532,0x0e},
                                std::pair<size_t,uint8_t>{0x5854c,0x0d},
                                std::pair<size_t,uint8_t>{0x584f3,0x10},
                                std::pair<size_t,uint8_t>{0x58370,0xc9},
                                std::pair<size_t,uint8_t>{0x5838b,0x06},
                                std::pair<size_t,uint8_t>{0x586a4,0x65},
                                std::pair<size_t,uint8_t>{0x58398,0x54}}) {
        const uint8_t saved = providerBytes[mutation.first];
        providerBytes[mutation.first] = mutation.second;
        assert(!E::verifyProvider(provider, ps));
        providerBytes[mutation.first] = saved;
        assert(E::verifyProvider(provider, ps));
    }
    // Every byte in the newly guarded code-20 route is exact. In particular,
    // the two rel32 branches must retain their audited targets.
    for (const auto range : {std::pair<size_t,size_t>{0x58494,0x5849e},
                             std::pair<size_t,size_t>{0x58555,0x5855f}}) {
        for (size_t offset = range.first; offset < range.second; ++offset) {
            providerBytes[offset] ^= 1;
            assert(!E::verifyProvider(provider, ps));
            providerBytes[offset] ^= 1;
            assert(E::verifyProvider(provider, ps));
        }
    }
    // Keep opcodes/compare immediates intact while changing only each route's
    // destination, so the explicit target checks fail closed as well.
    put32(providerBytes + 0x5849a, 0x58709 - 0x5849e);
    assert(!E::verifyProvider(provider, ps));
    put32(providerBytes + 0x5849a, 0x000000b7);
    assert(E::verifyProvider(provider, ps));
    put32(providerBytes + 0x5855b, 0x5875a - 0x5855f);
    assert(!E::verifyProvider(provider, ps));
    put32(providerBytes + 0x5855b, 0x000001aa);
    assert(E::verifyProvider(provider, ps));
    rebaseTextSegment(providerBytes);
    assert(E::verifyProvider(provider, ps)); // Rebased __TEXT vmaddr is accepted only at header base.
    put64(providerBytes + 32 + 24, reinterpret_cast<uintptr_t>(providerBytes) + 0x1000);
    assert(!E::verifyProvider(provider, ps));
    put64(providerBytes + 32 + 24, reinterpret_cast<uintptr_t>(providerBytes));
    for (auto kind : {E::DriverKind::Broadcom4331, E::DriverKind::Broadcom43224}) {
        initDriver(driverBytes, kind, ps);
        E::LoadedImage driver{driverBytes, 0x10000};
        const auto ds = driverSymbols(driverBytes, kind);
        assert(E::verifyDriver(driver, kind, ds, provider, ps));
        assert(E::mayAdvertiseCapability46(provider, ps, driver, kind, ds));

        // The real fixed guard rejects changed operations, branch destinations,
        // and the provider target. Only actual rel32 call displacements are variable.
        const size_t start = kind == E::DriverKind::Broadcom4331 ? 0xd350 : 0x95da;
        const size_t branchDisp = kind == E::DriverKind::Broadcom4331 ? 0x0d : 0x2c;
        const size_t code10Immediate = kind == E::DriverKind::Broadcom4331 ? 0x36 : 0x2e;
        const size_t tailJumpDisp = kind == E::DriverKind::Broadcom4331 ? 0x48 : 0x40;
        const uint8_t saved = driverBytes[start + code10Immediate];
        driverBytes[start + code10Immediate] ^= 1;
        assert(!E::verifyDriver(driver, kind, ds, provider, ps));
        driverBytes[start + code10Immediate] = saved;

        driverBytes[start + branchDisp] ^= 1;
        assert(!E::verifyDriver(driver, kind, ds, provider, ps));
        driverBytes[start + branchDisp] ^= 1;

        driverBytes[start + tailJumpDisp] ^= 1;
        assert(!E::verifyDriver(driver, kind, ds, provider, ps));
        driverBytes[start + tailJumpDisp] ^= 1;
        assert(E::verifyDriver(driver, kind, ds, provider, ps));

        auto wrongSymbols = ds;
        wrongSymbols.scanDone++;
        assert(!E::verifyDriver(driver, kind, wrongSymbols, provider, ps));
    }

    auto badProviderSymbols = ps;
    badProviderSymbols.postMessage++;
    assert(!E::verifyProvider(provider, badProviderSymbols));
    providerBytes[0x61fbc + 5] ^= 1; // Wrong cache-update code.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x61fbc + 5] ^= 1;
    providerBytes[0x5d9ba + 3] ^= 1; // Changed event metadata construction.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x5d9ba + 3] ^= 1;
    providerBytes[0x5d993 + 0x0c] ^= 1; // Changed zero-length entry branch.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x5d993 + 0x0c] ^= 1;
    providerBytes[0x5d993 + 0x1a] ^= 1; // Changed 0x7f0 BSD payload limit.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x5d993 + 0x1a] ^= 1;
    assert(E::verifyProvider(provider, ps));
    providerBytes[0x58709 + 3] ^= 1; // Provider's actual peer-manager route selector.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x58709 + 3] ^= 1;
    providerBytes[0x58709 + 9] ^= 1; // Route now skips the exact BSD fallback target.
    assert(!E::verifyProvider(provider, ps));
    providerBytes[0x58709 + 9] ^= 1;

    // UUID is read from the actual Mach-O command, not accepted as caller input.
    providerBytes[32 + 152 + 8] ^= 1;
    assert(!E::verifyProvider(provider, ps));

    initProvider(providerBytes);
    put32(providerBytes + 4, 7); // Wrong CPU family.
    assert(!E::verifyProvider(provider, ps));
    initProvider(providerBytes);
    put32(providerBytes + 12, 2); // Not a kext bundle.
    assert(!E::verifyProvider(provider, ps));
    initProvider(providerBytes);
    put32(providerBytes + 32 + 4, 144); // LC_SEGMENT_64 truncated around its section table.
    assert(!E::verifyProvider(provider, ps));
    initProvider(providerBytes);
    put32(providerBytes + 32 + 64, 2); // nsects must fit command size exactly.
    assert(!E::verifyProvider(provider, ps));
    initProvider(providerBytes);
    put32(providerBytes + 32 + 152 + 4, 32); // LC_UUID has fixed 24-byte shape.
    assert(!E::verifyProvider(provider, ps));
    // Increasing sizeofcmds makes the command fit the image, but does not
    // turn its extra bytes into a valid UUID command.
    put32(providerBytes + 20, 184);
    assert(!E::verifyProvider(provider, ps));
}

static std::vector<uint8_t> makeEvent(uint32_t eventCode, const char *ifname,
                                      const uint8_t *payload, size_t payloadSize) {
    std::vector<uint8_t> packet(E::KernelEventHeaderSize + E::InterfaceNameSize + payloadSize, 0);
    put32(packet.data(), static_cast<uint32_t>(packet.size()));
    put32(packet.data() + 4, E::NativeEventVendor);
    put32(packet.data() + 8, E::NativeEventClass);
    put32(packet.data() + 12, E::NativeEventSubclass);
    put32(packet.data() + 16, 9); // Native monotonically increasing event id.
    put32(packet.data() + 20, eventCode);
    const size_t nameSize = strlen(ifname);
    assert(nameSize < E::InterfaceNameSize);
    memcpy(packet.data() + E::KernelEventHeaderSize, ifname, nameSize);
    if (payloadSize) memcpy(packet.data() + E::KernelEventHeaderSize + E::InterfaceNameSize,
                            payload, payloadSize);
    return packet;
}

static void appendTLV(std::vector<uint8_t> &bytes, uint32_t type,
                      const uint8_t *value, size_t valueSize) {
    const size_t offset = bytes.size();
    bytes.resize(offset + E::LinkTLVHeaderSize + valueSize);
    put32(bytes.data() + offset, type);
    put32(bytes.data() + offset + 4, static_cast<uint32_t>(valueSize));
    if (valueSize) memcpy(bytes.data() + offset + E::LinkTLVHeaderSize,
                          value, valueSize);
}

// Independent repeated-search oracle for the pinned provider order. Unlike
// the production helper, it performs a complete bounded walk once per type.
static bool providerSelectionOracle(const uint8_t *bytes, size_t size,
                                    E::LinkEventProjection *out) {
    if (!out) return false;
    *out = {};
    if (!bytes || size < E::LinkTLVHeaderSize ||
        size > E::MaximumLinkTLVInputSize) return false;
    const uint32_t priority[] = {E::LinkTLVType4,
                                 E::LinkTLVInterfaceState,
                                 E::LinkTLVLinkState};
    for (uint32_t wanted : priority) {
        bool found = false;
        size_t selectedOffset = 0;
        size_t selectedSize = 0;
        size_t offset = 0;
        while (offset < size) {
            if (size - offset < E::LinkTLVHeaderSize) return false;
            const uint32_t type = get32(bytes + offset);
            const uint32_t length = get32(bytes + offset + 4);
            const size_t remaining = size - offset - E::LinkTLVHeaderSize;
            if (static_cast<size_t>(length) > remaining) return false;
            if (!found && type == wanted) {
                found = true;
                selectedOffset = offset + E::LinkTLVHeaderSize;
                selectedSize = length;
            }
            offset += E::LinkTLVHeaderSize + static_cast<size_t>(length);
        }
        if (offset != size) return false;
        if (found) {
            out->payload = bytes + selectedOffset;
            out->payloadSize = selectedSize;
            return true;
        }
    }
    return false;
}

static void linkProjectionContract() {
    const uint8_t a[] = {0x11, 0x12, 0x13};
    const uint8_t b[] = {0x21, 0x22, 0x23, 0x24};
    const uint8_t c[] = {0x31, 0x32, 0x33, 0x34, 0x35};
    const uint8_t d[] = {0x41, 0x42};
    auto compareWithOracle = [](const uint8_t *bytes, size_t size) {
        E::LinkEventProjection expected{};
        E::LinkEventProjection actual{};
        const bool oracle = providerSelectionOracle(bytes, size, &expected);
        const bool projected = E::projectLinkEventPayload(bytes, size, &actual);
        assert(projected == oracle);
        if (projected) {
            assert(actual.payload == expected.payload);
            assert(actual.payloadSize == expected.payloadSize);
            assert(!memcmp(actual.payload, expected.payload, actual.payloadSize));
        } else {
            assert(actual.payload == nullptr && actual.payloadSize == 0);
        }
    };

    // Outer provider priority wins over wire order; duplicate types use the
    // first occurrence. Values are deliberately nonzero and distinct.
    std::vector<uint8_t> priority;
    appendTLV(priority, E::LinkTLVLinkState, b, sizeof(b));
    appendTLV(priority, E::LinkTLVInterfaceState, a, sizeof(a));
    appendTLV(priority, E::LinkTLVType4, c, sizeof(c));
    appendTLV(priority, E::LinkTLVType4, d, sizeof(d));
    compareWithOracle(priority.data(), priority.size());
    E::LinkEventProjection projected{};
    assert(E::projectLinkEventPayload(priority.data(), priority.size(), &projected));
    assert(projected.payload == priority.data() + E::LinkTLVHeaderSize + sizeof(b) +
                                  E::LinkTLVHeaderSize + sizeof(a) + E::LinkTLVHeaderSize);
    assert(projected.payloadSize == sizeof(c) && !memcmp(projected.payload, c, sizeof(c)));

    std::vector<uint8_t> interfacePriority;
    appendTLV(interfacePriority, E::LinkTLVLinkState, b, sizeof(b));
    appendTLV(interfacePriority, E::LinkTLVInterfaceState, a, sizeof(a));
    appendTLV(interfacePriority, E::LinkTLVInterfaceState, d, sizeof(d));
    compareWithOracle(interfacePriority.data(), interfacePriority.size());
    assert(E::projectLinkEventPayload(interfacePriority.data(), interfacePriority.size(), &projected));
    assert(projected.payload == interfacePriority.data() + E::LinkTLVHeaderSize + sizeof(b) +
                                  E::LinkTLVHeaderSize);
    assert(projected.payloadSize == sizeof(a) && !memcmp(projected.payload, a, sizeof(a)));

    std::vector<uint8_t> firstLinkState;
    appendTLV(firstLinkState, E::LinkTLVLinkState, b, sizeof(b));
    appendTLV(firstLinkState, E::LinkTLVLinkState, d, sizeof(d));
    compareWithOracle(firstLinkState.data(), firstLinkState.size());
    assert(E::projectLinkEventPayload(firstLinkState.data(), firstLinkState.size(), &projected));
    assert(projected.payload == firstLinkState.data() + E::LinkTLVHeaderSize &&
           projected.payloadSize == sizeof(b) && !memcmp(projected.payload, b, sizeof(b)));

    // Empty values still have a real pointer at the header's +8 address and
    // win according to type priority.
    std::vector<uint8_t> emptyWins;
    appendTLV(emptyWins, E::LinkTLVType4, nullptr, 0);
    appendTLV(emptyWins, E::LinkTLVInterfaceState, a, sizeof(a));
    compareWithOracle(emptyWins.data(), emptyWins.size());
    assert(E::projectLinkEventPayload(emptyWins.data(), emptyWins.size(), &projected));
    assert(projected.payload == emptyWins.data() + E::LinkTLVHeaderSize &&
           projected.payloadSize == 0);

    // Unaligned input is byte-parsed safely. The maximum accepted opaque
    // value fills the transport bound exactly.
    std::vector<uint8_t> unaligned(priority.size() + 1);
    memcpy(unaligned.data() + 1, priority.data(), priority.size());
    compareWithOracle(unaligned.data() + 1, priority.size());
    std::vector<uint8_t> maximum;
    maximum.resize(E::MaximumLinkTLVInputSize);
    put32(maximum.data(), E::LinkTLVType4);
    put32(maximum.data() + 4, static_cast<uint32_t>(E::MaximumEventPayloadSize));
    for (size_t index = E::LinkTLVHeaderSize; index < maximum.size(); ++index)
        maximum[index] = static_cast<uint8_t>(index * 17U + 3U);
    compareWithOracle(maximum.data(), maximum.size());
    assert(E::projectLinkEventPayload(maximum.data(), maximum.size(), &projected));
    assert(projected.payloadSize == E::MaximumEventPayloadSize &&
           !memcmp(projected.payload, maximum.data() + E::LinkTLVHeaderSize,
                   E::MaximumEventPayloadSize));

    std::vector<uint8_t> noMatch;
    appendTLV(noMatch, 99, a, sizeof(a));
    compareWithOracle(noMatch.data(), noMatch.size());
    std::vector<uint8_t> truncatedTail = firstLinkState;
    truncatedTail.push_back(0x99);
    truncatedTail.push_back(0x88);
    E::LinkEventProjection failed{reinterpret_cast<const uint8_t *>(1), 123};
    assert(!E::projectLinkEventPayload(truncatedTail.data(), truncatedTail.size(), &failed));
    assert(failed.payload == nullptr && failed.payloadSize == 0);
    compareWithOracle(truncatedTail.data(), truncatedTail.size());

    std::vector<uint8_t> overlong;
    appendTLV(overlong, E::LinkTLVType4, a, sizeof(a));
    put32(overlong.data() + 4, 100);
    assert(!E::projectLinkEventPayload(overlong.data(), overlong.size(), &failed));
    assert(failed.payload == nullptr && failed.payloadSize == 0);
    assert(!E::projectLinkEventPayload(nullptr, 0, &failed));
    assert(!E::projectLinkEventPayload(priority.data(), priority.size(), nullptr));
    const auto *wrapping = reinterpret_cast<const uint8_t *>(UINTPTR_MAX - 3);
    assert(!E::projectLinkEventPayload(wrapping, E::LinkTLVHeaderSize, &failed));
}

static void eventPackets() {
    uint8_t filter[E::KernelEventFilterSize]{};
    put32(filter, 1); put32(filter + 4, 6); put32(filter + 8, 1);
    assert(E::matchesNativeWifiFilter(filter, sizeof(filter)));
    assert(!E::matchesNativeWifiFilter(filter, sizeof(filter) - 1));
    put32(filter + 4, 7); assert(!E::matchesNativeWifiFilter(filter, sizeof(filter)));

    E::EventView view{};
    auto scanDone = makeEvent(E::ScanDoneEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(scanDone.data(), scanDone.size(), "en7", view) == E::EventKind::ScanDone);
    assert(view.payloadSize == 0 && view.eventCode == 10);
    assert(E::inspectNativeEvent(scanDone.data(), scanDone.size(), "en0", view) == E::EventKind::Foreign);
    auto scanDoneWithData = makeEvent(E::ScanDoneEventCode, "en7", reinterpret_cast<const uint8_t *>("x"), 1);
    assert(E::inspectNativeEvent(scanDoneWithData.data(), scanDoneWithData.size(), "en7", view) ==
           E::EventKind::Malformed);
    auto cache = makeEvent(E::ScanCacheUpdatedEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(cache.data(), cache.size(), "en7", view) == E::EventKind::ScanCacheUpdated);
    auto ssid = makeEvent(E::SSIDChangedEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(ssid.data(), ssid.size(), "en7", view) ==
           E::EventKind::SSIDChanged);
    auto bssid = makeEvent(E::BSSIDChangedEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(bssid.data(), bssid.size(), "en7", view) ==
           E::EventKind::BSSIDChanged);
    auto rsn = makeEvent(E::RSNHandshakeCompleteEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(rsn.data(), rsn.size(), "en7", view) ==
           E::EventKind::RSNHandshakeComplete);
    const uint8_t eventBody[8] = {1,2,3,4,5,6,7,8};
    for (const uint32_t code : {E::SSIDChangedEventCode,
                                E::BSSIDChangedEventCode,
                                E::RSNHandshakeCompleteEventCode}) {
        auto extended = makeEvent(code, "en7", eventBody, sizeof(eventBody));
        // EventRouter only repairs the producer's pinned null/zero shape;
        // non-empty native shapes retain generic event classification.
        assert(E::inspectNativeEvent(extended.data(), extended.size(), "en7", view) ==
               E::EventKind::UnknownNative);
    }
    auto unknown = makeEvent(99, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(unknown.data(), unknown.size(), "en7", view) == E::EventKind::UnknownNative);
    auto event9 = makeEvent(9, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(event9.data(), event9.size(), "en7", view) ==
           E::EventKind::UnknownNative);
    put32(unknown.data(), static_cast<uint32_t>(unknown.size() + 1));
    assert(E::inspectNativeEvent(unknown.data(), unknown.size(), "en7", view) == E::EventKind::Malformed);

    uint8_t opaqueLinkValue[31]{};
    auto link = makeEvent(E::LinkStateEventCode, "en7",
                          opaqueLinkValue, sizeof(opaqueLinkValue));
    assert(E::inspectNativeEvent(link.data(), link.size(), "en7", view) == E::EventKind::LinkState);
    assert(view.payload == link.data() + E::KernelEventHeaderSize + E::InterfaceNameSize &&
           view.payloadSize == sizeof(opaqueLinkValue));
    auto emptyLink = makeEvent(E::LinkStateEventCode, "en7", nullptr, 0);
    assert(E::inspectNativeEvent(emptyLink.data(), emptyLink.size(), "en7", view) ==
           E::EventKind::LinkState);
    assert(view.payload == emptyLink.data() + emptyLink.size() && view.payloadSize == 0);
    std::vector<uint8_t> oversizedLink(E::KernelEventHeaderSize + E::InterfaceNameSize +
                                       E::MaximumEventPayloadSize + 1, 0);
    put32(oversizedLink.data(), static_cast<uint32_t>(oversizedLink.size()));
    put32(oversizedLink.data() + 4, E::NativeEventVendor);
    put32(oversizedLink.data() + 8, E::NativeEventClass);
    put32(oversizedLink.data() + 12, E::NativeEventSubclass);
    put32(oversizedLink.data() + 20, E::LinkStateEventCode);
    memcpy(oversizedLink.data() + E::KernelEventHeaderSize, "en7", 3);
    assert(E::inspectNativeEvent(oversizedLink.data(), oversizedLink.size(), "en7", view) ==
           E::EventKind::Malformed);
}

struct RouterFake {
    E::EventRouter *router = nullptr;
    bool locked = false;
    bool suppress = false;
    bool invokeNativeHelper = true;
    bool nestedCacheEventOnScanDone = false;
    uint32_t nestedLifecycleTriggerCode = 0;
    uint32_t nestedLifecycleCode = 0;
    bool helperOnForeignThread = false;
    bool wrongLinkPayloadPointer = false;
    bool wrongLinkPayloadSize = false;
    bool wrongLinkBSDName = false;
    bool wrongLifecycleEventCode = false;
    bool wrongLifecyclePayloadPointer = false;
    bool wrongLifecyclePayloadSize = false;
    bool wrongLifecycleBSDName = false;
    bool interruptContext = false;
    bool interruptsDisabled = false;
    uintptr_t threadToken = 1;
    unsigned postCalls = 0;
    unsigned helperCalls = 0;
    unsigned afterCalls = 0;
    unsigned contextViolationCalls = 0;
    unsigned suppressedCount = 0;
    unsigned suppressChecks = 0;
    bool originalReturnedBeforeAfter = false;
    bool bindingAvailable = true;
    bool ambiguousFamilyBinding = false;
    bool retireBindingOnPost = false;
    uint32_t events[128]{};
    void *eventPayloads[128]{};
    size_t eventPayloadSizes[128]{};
    char eventNames[128][E::InterfaceNameSize]{};
    unsigned eventCount = 0;
    uint8_t mismatchedLinkPayload[E::MaximumEventPayloadSize]{};
    void *target = reinterpret_cast<void *>(0x1234);
    char name[16] = "en7";
};
static RouterFake routerFake;
static void routerLock(void *value) {
    auto *f = static_cast<RouterFake *>(value);
    assert(!f->locked); f->locked = true;
}
static void routerUnlock(void *value) {
    auto *f = static_cast<RouterFake *>(value);
    assert(f->locked); f->locked = false;
}
static uintptr_t routerCurrentThread(void *context) {
    return static_cast<RouterFake *>(context)->threadToken;
}
static bool fakeLifecycleEventCode(uint32_t eventCode) {
    return eventCode == E::SSIDChangedEventCode ||
           eventCode == E::BSSIDChangedEventCode ||
           eventCode == E::RSNHandshakeCompleteEventCode;
}
static bool routerEventContextIsUnsafe(void *context) {
    auto *f = static_cast<RouterFake *>(context);
    return f->interruptContext || f->interruptsDisabled;
}
static bool routerLookupBinding(void *context, void *interface, E::DriverKind kind,
                                char bsdName[E::InterfaceNameSize]) {
    auto *f = static_cast<RouterFake *>(context);
    if (!f->bindingAvailable || interface != f->target ||
        (kind != E::DriverKind::Broadcom4331 &&
         (kind != E::DriverKind::Broadcom43224 || !f->ambiguousFamilyBinding))) return false;
    memcpy(bsdName, f->name, sizeof(f->name));
    return true;
}
static bool routerShouldSuppress(void *context, void *interface, uint32_t eventCode) {
    auto *f = static_cast<RouterFake *>(context);
    assert(interface == f->target);
    assert(eventCode == E::ScanDoneEventCode || eventCode == E::ScanCacheUpdatedEventCode);
    ++f->suppressChecks;
    return f->suppress;
}
static void routerAfterPost(void *context, void *interface, uint32_t eventCode) {
    auto *f = static_cast<RouterFake *>(context);
    assert(interface == f->target);
    assert(eventCode == E::ScanDoneEventCode || eventCode == E::ScanCacheUpdatedEventCode);
    assert(f->postCalls > f->afterCalls); // Original returned before callback.
    f->originalReturnedBeforeAfter = true;
    ++f->afterCalls;
}
static void routerEventContextViolation(void *context, void *interface,
                                        uint32_t eventCode) {
    auto *f = static_cast<RouterFake *>(context);
    assert(interface == f->target);
    assert(eventCode == E::ScanDoneEventCode ||
           eventCode == E::ScanCacheUpdatedEventCode);
    ++f->contextViolationCalls;
}
static void routerOriginalBSD(char *name, uint32_t eventCode, void *payload, size_t size) {
    auto *f = &routerFake;
    assert(name && (!strcmp(name, "en7") || !strcmp(name, "en8")));
    assert(f->eventCount < 128);
    ++f->helperCalls;
    f->events[f->eventCount] = eventCode;
    f->eventPayloads[f->eventCount] = payload;
    f->eventPayloadSizes[f->eventCount] = size;
    memcpy(f->eventNames[f->eventCount], name, E::InterfaceNameSize);
    ++f->eventCount;
}
static void routerOriginalPost(void *interface, uint32_t eventCode, void *payload, size_t size) {
    auto *f = &routerFake;
    assert(interface == f->target || interface == reinterpret_cast<void *>(0x9999));
    ++f->postCalls;
    if (f->invokeNativeHelper && (eventCode == E::ScanDoneEventCode ||
                                  eventCode == E::ScanCacheUpdatedEventCode ||
                                  eventCode == E::LinkStateEventCode ||
                                  fakeLifecycleEventCode(eventCode))) {
        const uintptr_t savedThread = f->threadToken;
        if (f->helperOnForeignThread) f->threadToken = 2;
        if (eventCode == E::LinkStateEventCode) {
            E::LinkEventProjection selected{};
            const bool projected = payload && providerSelectionOracle(
                static_cast<const uint8_t *>(payload), size, &selected);
            // The simulated original provider unwraps the selected TLV; if it
            // finds no supported type, it sends its unchanged input through
            // the ordinary fallback path.
            void *helperPayload = projected
                ? const_cast<uint8_t *>(selected.payload) : payload;
            size_t helperLength = projected ? selected.payloadSize : size;
            if (f->wrongLinkPayloadPointer)
                helperPayload = f->mismatchedLinkPayload;
            if (f->wrongLinkPayloadSize)
                helperLength = helperLength ? helperLength - 1 : 1;
            char wrongName[E::InterfaceNameSize] = "en8";
            f->router->bsdPostMessage(f->wrongLinkBSDName ? wrongName : f->name,
                                      eventCode, helperPayload, helperLength);
        } else if (fakeLifecycleEventCode(eventCode)) {
            void *helperPayload = payload;
            size_t helperLength = size;
            uint32_t helperCode = eventCode;
            if (f->wrongLifecycleEventCode) ++helperCode;
            if (f->wrongLifecyclePayloadPointer)
                helperPayload = f->mismatchedLinkPayload;
            if (f->wrongLifecyclePayloadSize) {
                helperPayload = nullptr;
                helperLength = 1;
            }
            char wrongName[E::InterfaceNameSize] = "en8";
            f->router->bsdPostMessage(f->wrongLifecycleBSDName ? wrongName : f->name,
                                      helperCode, helperPayload, helperLength);
        } else {
            f->router->bsdPostMessage(f->name, eventCode, payload, size);
        }
        f->threadToken = savedThread;
    }
    if (eventCode == E::ScanDoneEventCode && f->nestedCacheEventOnScanDone)
        f->router->postMessage(f->target, E::ScanCacheUpdatedEventCode, nullptr, 0);
    if (eventCode == f->nestedLifecycleTriggerCode &&
        fakeLifecycleEventCode(f->nestedLifecycleCode)) {
        const uint32_t nestedCode = f->nestedLifecycleCode;
        f->nestedLifecycleTriggerCode = 0;
        f->router->postMessage(f->target, nestedCode, nullptr, 0);
    }
    if (f->retireBindingOnPost) f->bindingAvailable = false;
}
static void eventRouterPaths() {
    std::vector<uint8_t> arena(0x90000);
    uint8_t *providerBytes = arena.data();
    uint8_t *driverBytes = arena.data() + 0x80000;
    initProvider(providerBytes);
    E::LoadedImage provider{providerBytes, 0x76000};
    const auto ps = providerSymbols(providerBytes);
    assert(E::verifyProvider(provider, ps));

    // Keep a second valid but distinct base for strict identity checks.
    std::vector<uint8_t> copiedProviderBytes(0x76000);
    initProvider(copiedProviderBytes.data());
    E::LoadedImage copiedProvider{copiedProviderBytes.data(), 0x76000};
    const auto copiedSymbols = providerSymbols(copiedProviderBytes.data());
    assert(E::verifyProvider(copiedProvider, copiedSymbols));

    initDriver(driverBytes, E::DriverKind::Broadcom4331, ps);
    E::LoadedImage driver{driverBytes, 0x10000};
    const auto ds = driverSymbols(driverBytes, E::DriverKind::Broadcom4331);

    routerFake = RouterFake{};
    E::EventRouter router;
    routerFake.router = &router;
    E::RouterAPI api{};
    api.context = &routerFake;
    api.lookupBoundInterface = routerLookupBinding;
    api.eventContextIsUnsafe = routerEventContextIsUnsafe;
    api.currentThread = routerCurrentThread;
    api.shouldSuppress = routerShouldSuppress;
    api.afterPost = routerAfterPost;
    api.eventContextViolation = routerEventContextViolation;
    api.scopeLock = {&routerFake, routerLock, routerUnlock};
    assert(router.configure(api, provider, ps));

    // A second configure is rejected, and the immutable pre-hook admission is
    // not usable until both routes and a driver are ready.
    assert(!router.configure(api, provider, ps));
    assert(!router.hasActiveVerifiedProvider(provider, ps));
    E::EventRouter configuredButInactive;
    assert(configuredButInactive.configure(api, provider, ps));
    assert(!configuredButInactive.hasActiveVerifiedProvider(provider, ps));

    // Simulate the two production route operations changing their entry bytes.
    providerBytes[0x58358] = 0xe9;
    providerBytes[0x5d993] = 0xe9;
    assert(!E::verifyProvider(provider, ps));

    assert(router.admitDriver(driver, E::DriverKind::Broadcom4331, ds));
    router.postMessageTrampoline() = routerOriginalPost;
    router.bsdPostMessageTrampoline() = routerOriginalBSD;
    assert(router.activateRoutes() && router.ready());
    assert(router.hasActiveVerifiedProvider(provider, ps));
    assert(!router.hasActiveVerifiedProvider(copiedProvider, copiedSymbols));
    E::LoadedImage wrongSize{providerBytes, provider.mappedSize - 1};
    assert(!router.hasActiveVerifiedProvider(wrongSize, ps));
    auto wrongSymbols = ps;
    wrongSymbols.getBSDName++;
    assert(!router.hasActiveVerifiedProvider(provider, wrongSymbols));
    wrongSymbols = ps;
    wrongSymbols.postMessage++;
    assert(!router.hasActiveVerifiedProvider(provider, wrongSymbols));
    wrongSymbols = ps;
    wrongSymbols.postMessageBSD++;
    assert(!router.hasActiveVerifiedProvider(provider, wrongSymbols));
    wrongSymbols = ps;
    wrongSymbols.scanManagerScanDone++;
    assert(!router.hasActiveVerifiedProvider(provider, wrongSymbols));
    wrongSymbols = ps;
    wrongSymbols.kevPostMsg++;
    assert(!router.hasActiveVerifiedProvider(provider, wrongSymbols));
    routerFake.bindingAvailable = false;
    assert(!router.mayAdvertiseCapability46(routerFake.target));
    routerFake.bindingAvailable = true;

    assert(router.mayAdvertiseCapability46(routerFake.target));

    // The provider's BSD fallback is delivered once. Observation by the
    // nested helper hook prevents the router from duplicating it on return.
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    assert(routerFake.postCalls == 1 && routerFake.helperCalls == 1 &&
           routerFake.afterCalls == 1 && routerFake.eventCount == 1 &&
           routerFake.events[0] == E::ScanDoneEventCode);

    // A gated route with no native helper call is repaired after all original
    // postMessage side effects, and code 15 is routed by the same rule.
    routerFake.invokeNativeHelper = false;
    router.postMessage(routerFake.target, E::ScanCacheUpdatedEventCode, nullptr, 0);
    assert(routerFake.postCalls == 2 && routerFake.helperCalls == 2 &&
           routerFake.afterCalls == 2 && routerFake.eventCount == 2 &&
           routerFake.events[1] == E::ScanCacheUpdatedEventCode);

    // During a multi-scan sequence only outward events are suppressed. The
    // original method still runs, and the completion callback runs afterward.
    routerFake.invokeNativeHelper = true;
    routerFake.suppress = true;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    assert(routerFake.postCalls == 3 && routerFake.helperCalls == 2 &&
           routerFake.afterCalls == 3 && routerFake.eventCount == 2);
    routerFake.invokeNativeHelper = false;
    router.postMessage(routerFake.target, E::ScanCacheUpdatedEventCode, nullptr, 0);
    assert(routerFake.postCalls == 4 && routerFake.helperCalls == 2 &&
           routerFake.afterCalls == 4 && routerFake.eventCount == 2);

    // A nested code-15 event has its own scope; it neither escapes nor marks
    // the outer code-10 route as delivered while a split scan is active.
    routerFake.invokeNativeHelper = true;
    routerFake.nestedCacheEventOnScanDone = true;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    routerFake.nestedCacheEventOnScanDone = false;
    assert(routerFake.postCalls == 6 && routerFake.helperCalls == 2 &&
           routerFake.afterCalls == 6 && routerFake.eventCount == 2);

    // A matching name/code from another thread is not attributed to the
    // synchronous runAction scope and cannot be swallowed by its suppression.
    routerFake.helperOnForeignThread = true;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    routerFake.helperOnForeignThread = false;
    assert(routerFake.postCalls == 7 && routerFake.helperCalls == 3 &&
           routerFake.afterCalls == 7 && routerFake.eventCount == 3 &&
           routerFake.events[2] == E::ScanDoneEventCode);

    // A same-thread interrupt cannot consume a synchronous scope or trigger
    // sequence advancement. Its native helper remains fail-open.
    routerFake.helperOnForeignThread = false;
    routerFake.interruptContext = true;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    routerFake.interruptContext = false;
    assert(routerFake.postCalls == 8 && routerFake.helperCalls == 4 &&
           routerFake.afterCalls == 7 && routerFake.eventCount == 4 &&
           routerFake.contextViolationCalls == 1 &&
           routerFake.events[3] == E::ScanDoneEventCode);
    routerFake.bindingAvailable = true;

    // Disabling interrupts while holding a lock is also unsafe for any
    // follow-up that may sleep, even when not in an interrupt handler.
    routerFake.interruptsDisabled = true;
    router.postMessage(routerFake.target, E::ScanCacheUpdatedEventCode, nullptr, 0);
    routerFake.interruptsDisabled = false;
    assert(routerFake.postCalls == 9 && routerFake.helperCalls == 5 &&
           routerFake.afterCalls == 7 && routerFake.eventCount == 5 &&
           routerFake.contextViolationCalls == 2 &&
           routerFake.events[4] == E::ScanCacheUpdatedEventCode);

    // The fixed provider emits only null/zero lifecycle bodies for these
    // three event codes. Each exact event is observed once through the native
    // helper path or repaired once when that path is absent.
    routerFake.suppress = false;
    const uint32_t lifecycleCodes[] = {
        E::SSIDChangedEventCode, E::BSSIDChangedEventCode,
        E::RSNHandshakeCompleteEventCode
    };
    const unsigned lifecycleAfterBase = routerFake.afterCalls;
    const unsigned lifecycleViolationBase = routerFake.contextViolationCalls;
    const unsigned lifecycleSuppressBase = routerFake.suppressChecks;
    for (const uint32_t code : lifecycleCodes) {
        unsigned beforePosts = routerFake.postCalls;
        unsigned beforeHelpers = routerFake.helperCalls;
        unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        router.postMessage(routerFake.target, code, nullptr, 0);
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1 &&
               routerFake.events[beforeEvents] == code &&
               routerFake.eventPayloads[beforeEvents] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents] == 0 &&
               !strcmp(routerFake.eventNames[beforeEvents], "en7"));

        beforePosts = routerFake.postCalls;
        beforeHelpers = routerFake.helperCalls;
        beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = false;
        router.postMessage(routerFake.target, code, nullptr, 0);
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1 &&
               routerFake.events[beforeEvents] == code &&
               routerFake.eventPayloads[beforeEvents] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents] == 0 &&
               !strcmp(routerFake.eventNames[beforeEvents], "en7"));
    }
    assert(routerFake.afterCalls == lifecycleAfterBase &&
           routerFake.contextViolationCalls == lifecycleViolationBase &&
           routerFake.suppressChecks == lifecycleSuppressBase);

    // Scope identity includes thread, BSD name, event code, pointer, and size.
    // A mismatched native helper is passed through; only the exact null/zero
    // event is then supplied by the synchronous fallback.
    auto sendLifecycleIdentityMismatch = [&](uint32_t code, bool wrongCode,
                                             bool wrongPointer, bool wrongSize,
                                             bool wrongName, bool wrongThread) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        const unsigned beforeAfter = routerFake.afterCalls;
        routerFake.invokeNativeHelper = true;
        routerFake.wrongLifecycleEventCode = wrongCode;
        routerFake.wrongLifecyclePayloadPointer = wrongPointer;
        routerFake.wrongLifecyclePayloadSize = wrongSize;
        routerFake.wrongLifecycleBSDName = wrongName;
        routerFake.helperOnForeignThread = wrongThread;
        router.postMessage(routerFake.target, code, nullptr, 0);
        routerFake.wrongLifecycleEventCode = false;
        routerFake.wrongLifecyclePayloadPointer = false;
        routerFake.wrongLifecyclePayloadSize = false;
        routerFake.wrongLifecycleBSDName = false;
        routerFake.helperOnForeignThread = false;
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 2 &&
               routerFake.eventCount == beforeEvents + 2 &&
               routerFake.afterCalls == beforeAfter);
        const unsigned native = beforeEvents;
        const unsigned fallback = beforeEvents + 1;
        assert(routerFake.events[fallback] == code &&
               routerFake.eventPayloads[fallback] == nullptr &&
               routerFake.eventPayloadSizes[fallback] == 0 &&
               !strcmp(routerFake.eventNames[fallback], "en7"));
        if (wrongCode) assert(routerFake.events[native] == code + 1);
        else assert(routerFake.events[native] == code);
        if (wrongPointer) assert(routerFake.eventPayloads[native] != nullptr);
        if (wrongSize) assert(routerFake.eventPayloadSizes[native] == 1);
        if (wrongName) assert(!strcmp(routerFake.eventNames[native], "en8"));
    };
    for (const uint32_t code : lifecycleCodes) {
        sendLifecycleIdentityMismatch(code, true, false, false, false, false);
        sendLifecycleIdentityMismatch(code, false, true, false, false, false);
        sendLifecycleIdentityMismatch(code, false, false, true, false, false);
        sendLifecycleIdentityMismatch(code, false, false, false, true, false);
        sendLifecycleIdentityMismatch(code, false, false, false, false, true);
    }
    assert(routerFake.afterCalls == lifecycleAfterBase &&
           routerFake.contextViolationCalls == lifecycleViolationBase &&
           routerFake.suppressChecks == lifecycleSuppressBase);

    // Nested lifecycle events get independent scopes and are each delivered
    // once. They never enter scan sequencing.
    for (size_t index = 0; index < sizeof(lifecycleCodes) / sizeof(lifecycleCodes[0]); ++index) {
        const uint32_t outer = lifecycleCodes[index];
        const uint32_t nested = lifecycleCodes[(index + 1) % 3];
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        routerFake.nestedLifecycleTriggerCode = outer;
        routerFake.nestedLifecycleCode = nested;
        router.postMessage(routerFake.target, outer, nullptr, 0);
        assert(routerFake.postCalls == beforePosts + 2 &&
               routerFake.helperCalls == beforeHelpers + 2 &&
               routerFake.eventCount == beforeEvents + 2 &&
               routerFake.events[beforeEvents] == outer &&
               routerFake.events[beforeEvents + 1] == nested &&
               routerFake.eventPayloads[beforeEvents] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents] == 0 &&
               routerFake.eventPayloads[beforeEvents + 1] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents + 1] == 0 &&
               routerFake.afterCalls == lifecycleAfterBase &&
               routerFake.suppressChecks == lifecycleSuppressBase);
    }

    // Identical nested events have the same observable scope key; the
    // innermost stack entry must be consumed first, then the outer entry.
    for (const uint32_t code : lifecycleCodes) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        routerFake.nestedLifecycleTriggerCode = code;
        routerFake.nestedLifecycleCode = code;
        router.postMessage(routerFake.target, code, nullptr, 0);
        assert(routerFake.postCalls == beforePosts + 2 &&
               routerFake.helperCalls == beforeHelpers + 2 &&
               routerFake.eventCount == beforeEvents + 2 &&
               routerFake.events[beforeEvents] == code &&
               routerFake.events[beforeEvents + 1] == code &&
               routerFake.eventPayloads[beforeEvents] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents] == 0 &&
               routerFake.eventPayloads[beforeEvents + 1] == nullptr &&
               routerFake.eventPayloadSizes[beforeEvents + 1] == 0 &&
               routerFake.afterCalls == lifecycleAfterBase &&
               routerFake.suppressChecks == lifecycleSuppressBase);
    }

    // Unsafe contexts remain fail-open: native BSD calls pass through, while
    // absent native calls are not repaired from an unsafe stack.
    for (const uint32_t code : lifecycleCodes) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        routerFake.interruptContext = true;
        router.postMessage(routerFake.target, code, nullptr, 0);
        routerFake.interruptContext = false;
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1 &&
               routerFake.events[beforeEvents] == code);

        const unsigned noHelperPosts = routerFake.postCalls;
        const unsigned noHelperCount = routerFake.helperCalls;
        const unsigned noHelperEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = false;
        routerFake.interruptsDisabled = true;
        router.postMessage(routerFake.target, code, nullptr, 0);
        routerFake.interruptsDisabled = false;
        assert(routerFake.postCalls == noHelperPosts + 1 &&
               routerFake.helperCalls == noHelperCount &&
               routerFake.eventCount == noHelperEvents &&
               routerFake.afterCalls == lifecycleAfterBase &&
               routerFake.contextViolationCalls == lifecycleViolationBase &&
               routerFake.suppressChecks == lifecycleSuppressBase);
    }

    // Detaching the retained interface during the original call prevents a
    // stale BSD fallback. These events do not advance scan state on retirement.
    for (const uint32_t code : lifecycleCodes) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = false;
        routerFake.bindingAvailable = true;
        routerFake.retireBindingOnPost = true;
        router.postMessage(routerFake.target, code, nullptr, 0);
        routerFake.retireBindingOnPost = false;
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers &&
               routerFake.eventCount == beforeEvents &&
               routerFake.afterCalls == lifecycleAfterBase &&
               routerFake.suppressChecks == lifecycleSuppressBase &&
               !routerFake.bindingAvailable);
    }
    routerFake.bindingAvailable = true;

    // Payload shapes outside the pinned producer contract pass through the
    // provider/helper path without creating a router fallback.
    uint8_t unexpectedLifecyclePayload = 0x5a;
    for (const uint32_t code : lifecycleCodes) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        void *payload = code == E::BSSIDChangedEventCode
            ? nullptr : &unexpectedLifecyclePayload;
        const size_t payloadSize = code == E::BSSIDChangedEventCode ? 1 : 0;
        router.postMessage(routerFake.target, code, payload, payloadSize);
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1 &&
               routerFake.events[beforeEvents] == code &&
               routerFake.eventPayloads[beforeEvents] == payload &&
               routerFake.eventPayloadSizes[beforeEvents] == payloadSize &&
               routerFake.afterCalls == lifecycleAfterBase &&
               routerFake.suppressChecks == lifecycleSuppressBase);
    }

    // Code 4 carries a TLV list into the original provider, which strips the
    // selected header before invoking the BSD helper. EventRouter mirrors the
    // complete bounded selection but keeps the resulting BSD payload opaque.
    routerFake.suppress = false;
    const uint8_t value13[] = {0xa1, 0x00, 0xa3};
    const uint8_t value14[] = {0xb1, 0xb2, 0x00, 0xb4, 0xb5};
    const uint8_t value4[] = {0xc1, 0x00};
    const uint8_t duplicate13[] = {0xd1, 0xd2, 0xd3, 0xd4};
    std::vector<uint8_t> tlv13, tlv14, tlv4;
    appendTLV(tlv13, E::LinkTLVInterfaceState, value13, sizeof(value13));
    appendTLV(tlv14, E::LinkTLVLinkState, value14, sizeof(value14));
    appendTLV(tlv4, E::LinkTLVType4, value4, sizeof(value4));

    auto sendProjected = [&](const std::vector<uint8_t> &wrapper,
                             bool nativeHelper, const uint8_t *expected,
                             size_t expectedSize) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        const unsigned beforeAfter = routerFake.afterCalls;
        routerFake.invokeNativeHelper = nativeHelper;
        router.postMessage(routerFake.target, E::LinkStateEventCode,
                           const_cast<uint8_t *>(wrapper.data()), wrapper.size());
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1 &&
               routerFake.afterCalls == beforeAfter);
        const unsigned index = beforeEvents;
        assert(routerFake.events[index] == E::LinkStateEventCode &&
               routerFake.eventPayloads[index] == expected &&
               routerFake.eventPayloadSizes[index] == expectedSize);
        if (expectedSize)
            assert(!memcmp(routerFake.eventPayloads[index], expected, expectedSize));
    };

    // The native and fallback paths preserve arbitrary (non-business-sized)
    // values byte-for-byte for each selected wire type.
    sendProjected(tlv13, true, tlv13.data() + E::LinkTLVHeaderSize, sizeof(value13));
    sendProjected(tlv13, false, tlv13.data() + E::LinkTLVHeaderSize, sizeof(value13));
    sendProjected(tlv14, true, tlv14.data() + E::LinkTLVHeaderSize, sizeof(value14));
    sendProjected(tlv14, false, tlv14.data() + E::LinkTLVHeaderSize, sizeof(value14));
    sendProjected(tlv4, true, tlv4.data() + E::LinkTLVHeaderSize, sizeof(value4));
    sendProjected(tlv4, false, tlv4.data() + E::LinkTLVHeaderSize, sizeof(value4));

    // Outer priority beats wire order, and repeated type 13 chooses the first
    // occurrence. The type-4 label is only a wire identifier here.
    std::vector<uint8_t> priority;
    appendTLV(priority, E::LinkTLVLinkState, value14, sizeof(value14));
    appendTLV(priority, E::LinkTLVInterfaceState, value13, sizeof(value13));
    appendTLV(priority, E::LinkTLVType4, value4, sizeof(value4));
    appendTLV(priority, E::LinkTLVType4, duplicate13, sizeof(duplicate13));
    const uint8_t *priorityValue = priority.data() + E::LinkTLVHeaderSize + sizeof(value14) +
        E::LinkTLVHeaderSize + sizeof(value13) + E::LinkTLVHeaderSize;
    sendProjected(priority, true, priorityValue, sizeof(value4));

    std::vector<uint8_t> duplicate;
    appendTLV(duplicate, E::LinkTLVInterfaceState, value13, sizeof(value13));
    appendTLV(duplicate, E::LinkTLVInterfaceState, duplicate13, sizeof(duplicate13));
    sendProjected(duplicate, false, duplicate.data() + E::LinkTLVHeaderSize,
                  sizeof(value13));

    // A zero-length selected value still has the non-null payload pointer at
    // header+8 and is eligible for exact scope matching and fallback repair.
    std::vector<uint8_t> emptyType4;
    appendTLV(emptyType4, E::LinkTLVType4, nullptr, 0);
    appendTLV(emptyType4, E::LinkTLVInterfaceState, value13, sizeof(value13));
    sendProjected(emptyType4, true,
                  emptyType4.data() + E::LinkTLVHeaderSize, 0);
    sendProjected(emptyType4, false,
                  emptyType4.data() + E::LinkTLVHeaderSize, 0);

    // Exact bridge admission maximum is the opaque maximum plus one header.
    std::vector<uint8_t> maximum(E::MaximumLinkTLVInputSize);
    put32(maximum.data(), E::LinkTLVType4);
    put32(maximum.data() + 4, static_cast<uint32_t>(E::MaximumEventPayloadSize));
    for (size_t i = E::LinkTLVHeaderSize; i < maximum.size(); ++i)
        maximum[i] = static_cast<uint8_t>(i * 19U + 7U);
    sendProjected(maximum, false, maximum.data() + E::LinkTLVHeaderSize,
                  E::MaximumEventPayloadSize);

    auto sendOriginalUnrepairable = [&](std::vector<uint8_t> &wrapper) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        router.postMessage(routerFake.target, E::LinkStateEventCode,
                           wrapper.data(), wrapper.size());
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 1 &&
               routerFake.eventCount == beforeEvents + 1);
        const unsigned index = beforeEvents;
        assert(routerFake.eventPayloads[index] == wrapper.data() &&
               routerFake.eventPayloadSizes[index] == wrapper.size() &&
               routerFake.events[index] == E::LinkStateEventCode);
    };

    // Malformed tails, inconsistent value lengths, and no matching type keep
    // the original provider's raw BSD route; the bridge opens no repair scope.
    std::vector<uint8_t> truncated = tlv13;
    truncated.push_back(0x99);
    truncated.push_back(0x88);
    std::vector<uint8_t> badLength = tlv13;
    put32(badLength.data() + 4, 0x7fffffffU);
    std::vector<uint8_t> noMatch;
    appendTLV(noMatch, 0, value13, sizeof(value13));
    appendTLV(noMatch, 99, value14, sizeof(value14));
    sendOriginalUnrepairable(truncated);
    sendOriginalUnrepairable(badLength);
    sendOriginalUnrepairable(noMatch);

    // The 2040-byte input bound is a bridge admission policy. Oversized input
    // is passed through to the provider and is never repaired by this hook.
    std::vector<uint8_t> overLimit(E::MaximumLinkTLVInputSize + 1);
    put32(overLimit.data(), E::LinkTLVType4);
    put32(overLimit.data() + 4,
          static_cast<uint32_t>(E::MaximumEventPayloadSize + 1));
    sendOriginalUnrepairable(overLimit);

    // Exact pointer/length, BSD name, and thread identity are all required to
    // consume a native observation. Mismatches pass through, then a valid
    // projected fallback is emitted once.
    auto sendIdentityMismatch = [&](bool wrongPointer, bool wrongSize,
                                    bool wrongName, bool wrongThread,
                                    const std::vector<uint8_t> &wrapper,
                                    const uint8_t *expected, size_t expectedSize) {
        const unsigned beforePosts = routerFake.postCalls;
        const unsigned beforeHelpers = routerFake.helperCalls;
        const unsigned beforeEvents = routerFake.eventCount;
        routerFake.invokeNativeHelper = true;
        routerFake.wrongLinkPayloadPointer = wrongPointer;
        routerFake.wrongLinkPayloadSize = wrongSize;
        routerFake.wrongLinkBSDName = wrongName;
        routerFake.helperOnForeignThread = wrongThread;
        router.postMessage(routerFake.target, E::LinkStateEventCode,
                           const_cast<uint8_t *>(wrapper.data()), wrapper.size());
        routerFake.wrongLinkPayloadPointer = false;
        routerFake.wrongLinkPayloadSize = false;
        routerFake.wrongLinkBSDName = false;
        routerFake.helperOnForeignThread = false;
        assert(routerFake.postCalls == beforePosts + 1 &&
               routerFake.helperCalls == beforeHelpers + 2 &&
               routerFake.eventCount == beforeEvents + 2);
        const unsigned first = beforeEvents;
        const unsigned fallback = beforeEvents + 1;
        assert(routerFake.events[first] == E::LinkStateEventCode &&
               routerFake.events[fallback] == E::LinkStateEventCode &&
               routerFake.eventPayloads[fallback] == expected &&
               routerFake.eventPayloadSizes[fallback] == expectedSize);
        if (wrongPointer)
            assert(routerFake.eventPayloads[first] == routerFake.mismatchedLinkPayload);
        else
            assert(routerFake.eventPayloads[first] == expected);
        if (wrongSize)
            assert(routerFake.eventPayloadSizes[first] == expectedSize - 1);
        if (wrongName) {
            assert(!strcmp(routerFake.eventNames[first], "en8"));
            assert(!strcmp(routerFake.eventNames[fallback], "en7"));
        }
        if (expectedSize)
            assert(!memcmp(routerFake.eventPayloads[fallback], expected, expectedSize));
    };
    sendIdentityMismatch(true, false, false, false, tlv13,
                         tlv13.data() + E::LinkTLVHeaderSize, sizeof(value13));
    sendIdentityMismatch(false, true, false, false, tlv14,
                         tlv14.data() + E::LinkTLVHeaderSize, sizeof(value14));
    sendIdentityMismatch(false, false, true, false, tlv13,
                         tlv13.data() + E::LinkTLVHeaderSize, sizeof(value13));
    sendIdentityMismatch(false, false, false, true, tlv14,
                         tlv14.data() + E::LinkTLVHeaderSize, sizeof(value14));

    // If the retained interface terminates during the original method, do not
    // synthesize a BSD notification or advance the sequence for the stale enN.
    routerFake.invokeNativeHelper = false;
    const unsigned beforeRetirePosts = routerFake.postCalls;
    const unsigned beforeRetireHelpers = routerFake.helperCalls;
    const unsigned beforeRetireEvents = routerFake.eventCount;
    routerFake.retireBindingOnPost = true;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, nullptr, 0);
    routerFake.retireBindingOnPost = false;
    assert(routerFake.postCalls == beforeRetirePosts + 1 &&
           routerFake.helperCalls == beforeRetireHelpers &&
           routerFake.afterCalls == 7 &&
           routerFake.eventCount == beforeRetireEvents &&
           !routerFake.bindingAvailable);
    routerFake.bindingAvailable = true;

    // Non-primary interfaces and non-empty/other event shapes pass through
    // without sequence callbacks or synthetic scan notifications.
    routerFake.invokeNativeHelper = false;
    const unsigned before = routerFake.postCalls;
    const unsigned beforeManagedEvents = routerFake.eventCount;
    const unsigned beforeManagedHelpers = routerFake.helperCalls;
    router.postMessage(reinterpret_cast<void *>(0x9999), E::ScanDoneEventCode, nullptr, 0);
    uint8_t payload = 1;
    router.postMessage(routerFake.target, E::ScanDoneEventCode, &payload, 1);
    router.postMessage(routerFake.target, E::LinkStateEventCode, nullptr, 0);
    assert(routerFake.postCalls == before + 3 && routerFake.afterCalls == 7 &&
           routerFake.eventCount == beforeManagedEvents);

    // Managed completion bypasses postMessage, so it cannot re-enter scan
    // manager cleanup or the event suppressor. It still rejects contexts in
    // which its BSD helper might allocate or block.
    routerFake.interruptsDisabled = true;
    assert(!router.publishManaged(routerFake.target, E::ScanDoneEventCode));
    routerFake.interruptsDisabled = false;
    assert(router.publishManaged(routerFake.target, E::ScanDoneEventCode));
    assert(routerFake.postCalls == before + 3 &&
           routerFake.helperCalls == beforeManagedHelpers + 1 &&
           routerFake.eventCount == beforeManagedEvents + 1 &&
           routerFake.events[beforeManagedEvents] == E::ScanDoneEventCode);

    // A second exact family can be admitted too; an object accepted as both
    // families is rejected as ambiguous rather than arbitrarily routed.
    initDriver(driverBytes, E::DriverKind::Broadcom43224, ps);
    E::LoadedImage driver43224{driverBytes, 0x10000};
    const auto ds43224 = driverSymbols(driverBytes, E::DriverKind::Broadcom43224);
    assert(router.admitDriver(driver43224, E::DriverKind::Broadcom43224, ds43224));
    routerFake.ambiguousFamilyBinding = true;
    assert(!router.mayAdvertiseCapability46(routerFake.target));
}

int main() {
    bindingCreationRetirementRace();
    imageAdmission(); eventPackets(); linkProjectionContract(); eventRouterPaths();
}
'''


class LegacyEventContractTests(unittest.TestCase):
    def test_event_and_scan_capability_contract(self):
        with tempfile.TemporaryDirectory(prefix="legacy-event-contract-") as temporary:
            source = pathlib.Path(temporary) / "test.cpp"
            binary = pathlib.Path(temporary) / "test"
            source.write_text(HARNESS)
            subprocess.run(
                ["clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer", "-g",
                 "-DAIRPORT_BRCM_EVENT_ROUTER_HOST_TEST=1",
                 "-I", str(PROJECT / "src"), str(source),
                 str(PROJECT / "src/legacy_wifi_compat/event_router.cpp"), "-o", str(binary)], check=True
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
