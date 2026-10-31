"""Sanitizer-backed runtime admission tests over retained child binaries."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
CHILD_4331 = PROJECT / "build/research/oclp-legacy/elcap-analysis-inputs/AirPortBrcm4331.bin"
CHILD_43224 = PROJECT / "build/research/oclp-legacy/elcap-analysis-inputs/AppleAirPortBrcm43224.bin"

MOCK_PATCHER = r'''
#ifndef MOCK_HEADERS_KERN_PATCHER_HPP
#define MOCK_HEADERS_KERN_PATCHER_HPP
#include <stddef.h>
#include <stdint.h>
using mach_vm_address_t = uint64_t;
class KernelPatcher {
public:
    enum class Error { NoError, NoSymbolFound, InvalidSymbolFound };
    static constexpr size_t KernelID = 0;
    using Resolver = mach_vm_address_t (*)(void *, size_t, const char *);
    void *context = nullptr;
    Resolver resolver = nullptr;
    Error error = Error::NoError;
    size_t clearCount = 0;
    size_t solveCount = 0;

    void clearError() { ++clearCount; error = Error::NoError; }
    Error getError() { return error; }
    mach_vm_address_t solveSymbol(size_t id, const char *name) {
        ++solveCount;
        const mach_vm_address_t result = resolver ? resolver(context, id, name) : 0;
        if (!result && error == Error::NoError) error = Error::NoSymbolFound;
        return result;
    }
    mach_vm_address_t solveSymbol(size_t id, const char *name,
                                  mach_vm_address_t start, size_t size,
                                  bool = false) {
        const mach_vm_address_t result = solveSymbol(id, name);
        if (!result) return 0;
        if (result < start || result - start >= size) {
            error = Error::InvalidSymbolFound;
            return 0;
        }
        return result;
    }
};
#endif
'''

HARNESS = r'''
#include "legacy_wifi_compat/disassociate_admission.hpp"
#include "legacy_wifi_compat/event_contracts.hpp"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace D = LegacyWiFi::DisassociateChildContract;
namespace A = LegacyWiFi::DisassociateAdmission;
namespace E = LegacyWiFi::EventContracts;

constexpr size_t ChildKextIndex = 19;

struct ResolverState {
    uintptr_t base = 0;
    size_t size = 0;
    D::ChildKind child = D::Brcm4331;
    std::string failName;
    std::string wrongAddressName;
    size_t imageLookups = 0;
    size_t kernelLookups = 0;
    size_t functionLookups = 0;
    size_t routeLookups = 0;
};

static uintptr_t importTarget(const ResolverState &state, size_t importIndex) {
    return state.base + state.size + 0x1000 + importIndex * 0x100;
}

static mach_vm_address_t resolveName(void *context, size_t id, const char *name) {
    ResolverState &state = *static_cast<ResolverState *>(context);
    if (!name || state.failName == name) return 0;
    if (id == ChildKextIndex) {
        for (size_t index = 0; index < D::FunctionCount; ++index) {
            const D::FunctionContract &function =
                D::Functions[static_cast<size_t>(state.child)][index];
            if (function.symbol && strcmp(function.symbol, name) == 0) {
                ++state.functionLookups;
                const uintptr_t address = state.base + function.start;
                return address + (state.wrongAddressName == name ? 1 : 0);
            }
        }
        for (size_t index = 0; index < D::RouteSymbolCount; ++index) {
            const D::RouteSymbolContract &symbol = D::RouteSymbols[index];
            if (symbol.child == state.child && symbol.symbol &&
                strcmp(symbol.symbol, name) == 0) {
                ++state.routeLookups;
                const uintptr_t address = state.base + symbol.address;
                return address + (state.wrongAddressName == name ? 1 : 0);
            }
        }
        return 0;
    }
    if (id == KernelPatcher::KernelID) {
        ++state.kernelLookups;
        for (size_t index = 0; index < D::ImportCount; ++index) {
            if (strcmp(D::ImportNames[index], name) == 0)
                return importTarget(state, index);
        }
        return 0;
    }
    ++state.imageLookups;
    return 0;
}

struct Fixture {
    std::vector<uint8_t> bytes;
    uintptr_t base() const { return reinterpret_cast<uintptr_t>(bytes.data()); }
};

static void writeRel32(std::vector<uint8_t> &bytes, uintptr_t base,
                       size_t instruction, uintptr_t target) {
    const uintptr_t returnPC = base + instruction + 5;
    const int64_t delta = target >= returnPC
        ? static_cast<int64_t>(target - returnPC)
        : -static_cast<int64_t>(returnPC - target);
    assert(delta >= INT32_MIN && delta <= INT32_MAX);
    const int32_t encoded = static_cast<int32_t>(delta);
    memcpy(bytes.data() + instruction + 1, &encoded, sizeof(encoded));
}

static Fixture loadFixture(const char *path, D::ChildKind child) {
    std::ifstream file(path, std::ios::binary);
    Fixture fixture;
    fixture.bytes.assign(std::istreambuf_iterator<char>(file), {});
    assert(!fixture.bytes.empty());
    const uintptr_t base = fixture.base();
    for (size_t index = 0; index < D::ExternalCallCount; ++index) {
        const D::ExternalCall &call = D::ExternalCalls[index];
        if (call.child != child) continue;
        writeRel32(fixture.bytes, base, call.instruction,
                   base + fixture.bytes.size() + 0x1000 +
                       static_cast<size_t>(call.target) * 0x100);
    }
    return fixture;
}

static void initPatcher(KernelPatcher &patcher, ResolverState &state,
                        const Fixture &fixture, D::ChildKind child) {
    state.base = fixture.base();
    state.size = fixture.bytes.size();
    state.child = child;
    patcher.context = &state;
    patcher.resolver = &resolveName;
    patcher.error = KernelPatcher::Error::NoSymbolFound;
}

static void assertEmpty(const A::Admission &admission) {
    assert(!admission.ready);
    assert(admission.child == D::Brcm4331);
    assert(admission.index == 0);
    assert(admission.image.bytes == nullptr && admission.image.size == 0 &&
           admission.image.base == 0);
    for (size_t index = 0; index < D::FunctionCount; ++index)
        assert(admission.symbols.addresses[index] == 0);
    for (size_t index = 0; index < D::ImportCount; ++index)
        assert(admission.imports.addresses[index] == 0);
    for (size_t index = 0; index < D::RouteSymbolCount; ++index)
        assert(admission.routeSymbols.addresses[index] == 0);
    for (uint8_t byte : admission.imageUUID) assert(byte == 0);
}

static size_t expectedImportCount(D::ChildKind child) {
    bool used[D::ImportCount]{};
    for (size_t index = 0; index < D::ExternalCallCount; ++index) {
        const D::ExternalCall &call = D::ExternalCalls[index];
        if (call.child == child) used[static_cast<size_t>(call.target)] = true;
    }
    size_t count = 0;
    for (bool value : used) if (value) ++count;
    return count;
}

static size_t expectedFunctionCount(D::ChildKind child) {
    size_t count = 0;
    for (size_t index = 0; index < D::FunctionCount; ++index)
        if (D::Functions[static_cast<size_t>(child)][index].symbol) ++count;
    return count;
}

static size_t expectedRouteSymbolCount(D::ChildKind child) {
    size_t count = 0;
    for (size_t index = 0; index < D::RouteSymbolCount; ++index)
        if (D::RouteSymbols[index].child == child) ++count;
    return count;
}

static void exerciseChild(const char *path, D::ChildKind child) {
    const size_t childIndex = static_cast<size_t>(child);
    Fixture fixture = loadFixture(path, child);
    ResolverState state;
    KernelPatcher patcher;
    initPatcher(patcher, state, fixture, child);

    A::Admission admitted{};
    assert(A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                          fixture.bytes.size(), child, &admitted));
    assert(admitted.ready && admitted.child == child &&
           admitted.index == ChildKextIndex);
    assert(admitted.image.base == fixture.base() &&
           admitted.image.size == fixture.bytes.size() &&
           admitted.image.bytes == fixture.bytes.data());
    assert(memcmp(admitted.imageUUID, D::SourceUUID[childIndex], 16) == 0);
    assert(patcher.error == KernelPatcher::Error::NoError);
    assert(state.functionLookups == expectedFunctionCount(child) &&
           state.routeLookups == expectedRouteSymbolCount(child));
    assert(state.kernelLookups == expectedImportCount(child));
    assert(patcher.clearCount == patcher.solveCount * 2 + 1);

    // A ready result is immutable and cannot be overwritten by a second
    // verification attempt after a caller may already have routed this image.
    const uintptr_t savedBase = admitted.image.base;
    const size_t savedIndex = admitted.index;
    const size_t savedSolveCount = patcher.solveCount;
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, &admitted));
    assert(admitted.ready && admitted.image.base == savedBase &&
           admitted.index == savedIndex);
    assert(patcher.solveCount == savedSolveCount);

    // A fresh output can independently verify the same image; there is no
    // global one-shot cache or route installation hidden in this API.
    A::Admission repeated{};
    const size_t oldSolveCount = patcher.solveCount;
    assert(A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                          fixture.bytes.size(), child, &repeated));
    assert(repeated.ready && patcher.solveCount > oldSolveCount);

    // Missing function symbols fail individually and leave no partial output.
    const char *firstFunction =
        D::Functions[childIndex][D::AssocChangeState].symbol;
    assert(firstFunction);
    ResolverState missingFunctionState;
    initPatcher(patcher, missingFunctionState, fixture, child);
    missingFunctionState.failName = firstFunction;
    A::Admission missingFunction{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, &missingFunction));
    assertEmpty(missingFunction);
    assert(patcher.error == KernelPatcher::Error::NoError);

    for (size_t index = 0; index < D::RouteSymbolCount; ++index) {
        if (D::RouteSymbols[index].child != child) continue;
        ResolverState missingRouteState;
        initPatcher(patcher, missingRouteState, fixture, child);
        missingRouteState.failName = D::RouteSymbols[index].symbol;
        A::Admission missingRoute{};
        assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                               fixture.bytes.size(), child, &missingRoute));
        assertEmpty(missingRoute);
    }

    // A missing external target is rejected after an independent KernelID
    // lookup, not inferred from a callsite address.
    size_t missingImportIndex = D::ImportCount;
    for (size_t index = 0; index < D::ExternalCallCount; ++index) {
        if (D::ExternalCalls[index].child == child) {
            missingImportIndex = static_cast<size_t>(D::ExternalCalls[index].target);
            break;
        }
    }
    assert(missingImportIndex < D::ImportCount);
    ResolverState missingImportState;
    initPatcher(patcher, missingImportState, fixture, child);
    missingImportState.failName = D::ImportNames[missingImportIndex];
    A::Admission missingImport{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, &missingImport));
    assertEmpty(missingImport);

    // A found but wrong in-image symbol address must fail the production DCC
    // check. Import and symbol resolution alone do not grant admission.
    ResolverState wrongAddressState;
    initPatcher(patcher, wrongAddressState, fixture, child);
    wrongAddressState.wrongAddressName = firstFunction;
    A::Admission wrongAddress{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, &wrongAddress));
    assertEmpty(wrongAddress);

    // The Mach-O UUID is read from LC_UUID; no caller-supplied UUID can make a
    // changed image pass.
    E::Detail::ParsedImage parsed{};
    assert(E::Detail::parseImage({fixture.bytes.data(), fixture.bytes.size()}, parsed));
    const size_t uuidOffset = static_cast<size_t>(parsed.uuid - fixture.bytes.data());
    fixture.bytes[uuidOffset] ^= 0x80;
    ResolverState changedUUIDState;
    initPatcher(patcher, changedUUIDState, fixture, child);
    A::Admission changedUUID{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, &changedUUID));
    assertEmpty(changedUUID);
    fixture.bytes[uuidOffset] ^= 0x80;

    ResolverState shortState;
    initPatcher(patcher, shortState, fixture, child);
    A::Admission shortImage{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(), 0x1000,
                           child, &shortImage));
    assertEmpty(shortImage);

    ResolverState badKindState;
    initPatcher(patcher, badKindState, fixture, child);
    A::Admission badKind{};
    const D::ChildKind wrongChild = child == D::Brcm4331
        ? D::Brcm43224 : D::Brcm4331;
    badKindState.child = wrongChild;
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), wrongChild, &badKind));
    assertEmpty(badKind);

    ResolverState invalidKindState;
    initPatcher(patcher, invalidKindState, fixture, child);
    A::Admission invalidKind{};
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), static_cast<D::ChildKind>(9),
                           &invalidKind));
    assertEmpty(invalidKind);
    assert(patcher.error == KernelPatcher::Error::NoError);
    assert(invalidKindState.imageLookups == 0 && invalidKindState.kernelLookups == 0);

    ResolverState invalidBoundsState;
    initPatcher(patcher, invalidBoundsState, fixture, child);
    A::Admission invalidBounds{};
    assert(!A::verifyChild(patcher, ChildKextIndex, UINTPTR_MAX - 8, 16,
                           child, &invalidBounds));
    assertEmpty(invalidBounds);
    assert(!A::verifyChild(patcher, ChildKextIndex, fixture.base(),
                           fixture.bytes.size(), child, nullptr));
}

int main(int argc, char **argv) {
    assert(argc == 3);
    exerciseChild(argv[1], D::Brcm4331);
    exerciseChild(argv[2], D::Brcm43224);
    puts("disassociate child admission passed for both retained binaries");
}
'''


class DisassociateAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not CHILD_4331.is_file() or not CHILD_43224.is_file():
            raise unittest.SkipTest("retained child binaries are not available")
        xcrun = shutil.which("xcrun")
        clang = shutil.which("clang++")
        if not xcrun and not clang:
            raise unittest.SkipTest("clang++ is required for the admission harness")

        cls.temp = tempfile.TemporaryDirectory(prefix="legacy-disassociate-admission-")
        root = Path(cls.temp.name)
        mock_header = root / "mock/Headers/kern_patcher.hpp"
        mock_header.parent.mkdir(parents=True)
        mock_header.write_text(MOCK_PATCHER)
        source = root / "admission_harness.cpp"
        binary = root / "admission_harness"
        source.write_text(HARNESS)
        compiler = [xcrun, "clang++"] if xcrun else [clang]
        subprocess.run(
            compiler + [
                "-std=c++14", "-Wall", "-Wextra", "-Werror",
                "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                "-I", str(root / "mock"), "-I", str(PROJECT / "src"),
                str(PROJECT / "src/legacy_wifi_compat/disassociate_admission.cpp"),
                str(source), "-o", str(binary),
            ], check=True, capture_output=True, text=True, timeout=90,
        )
        cls.binary = binary

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    def test_production_admission_against_retained_child_binaries(self):
        result = subprocess.run(
            [str(self.binary), str(CHILD_4331), str(CHILD_43224)],
            check=True, capture_output=True, text=True, timeout=90,
        )
        self.assertIn("passed for both retained binaries", result.stdout)


if __name__ == "__main__":
    unittest.main()
