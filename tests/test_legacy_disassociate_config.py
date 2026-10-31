"""Tests for the actual disassociate-config implementation with mocked IOKit APIs."""
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT / "src/legacy_wifi_compat/disassociate_config.cpp"
INSTALL_SOURCE = PROJECT / "src/legacy_wifi_compat/legacy_install.cpp"

MOCK_HEADERS = {
    "IOKit/IORegistryEntry.h": r'''#ifndef MOCK_IOREGISTRYENTRY_H
#define MOCK_IOREGISTRYENTRY_H
#include <stddef.h>
#include <stdint.h>

struct IORegistryPlane {};
class OSObject;
typedef uint32_t IOOptionBits;

enum : uint32_t {
    kIORegistryIterateRecursively = 0x00000001,
    kIORegistryIterateParents = 0x00000002,
};

extern const IORegistryPlane *gIOServicePlane;

class IORegistryEntry {
public:
    virtual ~IORegistryEntry() = default;
    virtual OSObject *copyProperty(const char *key,
                                  const IORegistryPlane *plane,
                                  uint32_t options) const;
};

#define OSDynamicCast(type, object) dynamic_cast<type *>(object)
#endif
''',
    "IOKit/IOService.h": r'''#ifndef MOCK_IOSERVICE_H
#define MOCK_IOSERVICE_H
#include <IOKit/IORegistryEntry.h>

class IOService : public IORegistryEntry {
public:
    virtual IOService *getProvider() const;
};
#endif
''',
    "libkern/c++/OSData.h": r'''#ifndef MOCK_OSDATA_H
#define MOCK_OSDATA_H
#include <IOKit/IORegistryEntry.h>
#include <stddef.h>
#include <stdint.h>

class OSObject {
public:
    OSObject() : retainCalls(0), releaseCalls(0) {}
    virtual ~OSObject() = default;
    virtual void retain() { ++retainCalls; }
    virtual void release() { ++releaseCalls; }
    unsigned retainCalls;
    unsigned releaseCalls;
};

class OSData : public OSObject {
public:
    OSData(const uint8_t *bytes, size_t length, bool forceNull = false)
        : calls_(0), lastStart_(0), lastLength_(0), length_(length),
          forceNull_(forceNull) {
        for (size_t i = 0; i < sizeof(bytes_); ++i) bytes_[i] = 0;
        for (size_t i = 0; i < length && i < sizeof(bytes_); ++i) bytes_[i] = bytes[i];
    }
    const void *getBytesNoCopy(unsigned int start, unsigned int length) const {
        ++calls_;
        lastStart_ = start;
        lastLength_ = length;
        if (forceNull_ || start > length_ || length > length_ - start) return nullptr;
        return bytes_ + start;
    }
    mutable unsigned calls_;
    mutable unsigned lastStart_;
    mutable unsigned lastLength_;
private:
    uint8_t bytes_[16];
    size_t length_;
    bool forceNull_;
};

#endif
''',
    "pexpert/pexpert.h": r'''#ifndef MOCK_PEXPERT_H
#define MOCK_PEXPERT_H
typedef int boolean_t;
extern "C" boolean_t PE_parse_boot_argn(const char *name, void *value, int size);
#endif
''',
}

HARNESS = r'''
#include "legacy_wifi_compat/disassociate_config.hpp"
#include <IOKit/IOService.h>
#include <libkern/c++/OSData.h>
#include <pexpert/pexpert.h>
#include <assert.h>
#include <initializer_list>
#include <stdint.h>
#include <string.h>

namespace DC = LegacyWiFi::DisassociateConfig;

const IORegistryPlane kPlane {};
const IORegistryPlane *gIOServicePlane = &kPlane;

struct BootArg {
    const char *name;
    bool present;
    uint32_t value;
    bool mutateWhenMissing;
};

static BootArg useArg {"wlan.pcie.useOLYHALDriver", false, 0, false};
static BootArg overrideArg {"wlan.debug.EEparams.enhancedDisAssociationInfo",
                             false, 0, false};
static unsigned useReads;
static unsigned overrideReads;

struct PropertyState {
    OSObject *value = nullptr;
    unsigned calls = 0;
    const char *key = nullptr;
    const IORegistryPlane *plane = nullptr;
    uint32_t options = 0;
    const IORegistryEntry *receiver = nullptr;
};
static PropertyState propertyState;

struct ProviderState {
    IOService *provider = nullptr;
    unsigned calls = 0;
    const IOService *receiver = nullptr;
};
static ProviderState providerState;

extern "C" boolean_t PE_parse_boot_argn(const char *name, void *value, int size) {
    BootArg *arg = nullptr;
    if (!strcmp(name, useArg.name)) { arg = &useArg; ++useReads; }
    if (!strcmp(name, overrideArg.name)) { arg = &overrideArg; ++overrideReads; }
    assert(arg != nullptr);
    if (arg->present) {
        assert(value != nullptr && size > 0 && size <= (int)sizeof(arg->value));
        memcpy(value, &arg->value, (size_t)size);
        return 1;
    }
    if (arg->mutateWhenMissing && value && size > 0) {
        memset(value, 0xff, (size_t)size);
    }
    return 0;
}

OSObject *IORegistryEntry::copyProperty(const char *key,
                                        const IORegistryPlane *plane,
                                        uint32_t options) const {
    ++propertyState.calls;
    propertyState.key = key;
    propertyState.plane = plane;
    propertyState.options = options;
    propertyState.receiver = this;
    if (propertyState.value) propertyState.value->retain();
    return propertyState.value;
}

IOService *IOService::getProvider() const {
    ++providerState.calls;
    providerState.receiver = this;
    return providerState.provider;
}

static void reset() {
    useArg.present = false; useArg.value = 0; useArg.mutateWhenMissing = false;
    overrideArg.present = false; overrideArg.value = 0;
    overrideArg.mutateWhenMissing = false;
    useReads = overrideReads = 0;
    propertyState = PropertyState {};
    providerState = ProviderState {};
}

static void validRootAndExactOptions() {
    reset();
    IOService controller;
    const uint32_t word = 0x80000001U;
    OSData property(reinterpret_cast<const uint8_t *>(&word), sizeof(word));
    propertyState.value = &property;
    bool enabled = false;
    assert(DC::read(&controller, &enabled));
    assert(enabled);
    assert(useReads == 1 && overrideReads == 1);
    assert(providerState.calls == 0);
    assert(propertyState.calls == 1 && propertyState.receiver == &controller);
    assert(!strcmp(propertyState.key, "wlan.enterprise.params"));
    assert(propertyState.plane == gIOServicePlane);
    assert(propertyState.options ==
           (kIORegistryIterateParents | kIORegistryIterateRecursively));
    assert(property.calls_ == 1 && property.lastStart_ == 0 && property.lastLength_ == 4);
    assert(property.retainCalls == 1 && property.releaseCalls == 1);
}

static void sourceBootArgChoosesControllerOrProvider() {
    reset();
    IOService controller;
    IOService provider;
    const uint32_t one = 1;
    OSData property(reinterpret_cast<const uint8_t *>(&one), sizeof(one));
    propertyState.value = &property;

    useArg.present = true;
    useArg.value = 1;
    bool enabled = false;
    assert(DC::read(&controller, &enabled) && enabled);
    assert(propertyState.receiver == &controller && providerState.calls == 0);

    reset();
    propertyState.value = &property;
    providerState.provider = &provider;
    useArg.present = true;
    useArg.value = 0;
    enabled = false;
    assert(DC::read(&controller, &enabled) && enabled);
    assert(providerState.calls == 1 && providerState.receiver == &controller);
    assert(propertyState.receiver == &provider);

    reset();
    propertyState.value = &property;
    providerState.provider = &provider;
    useArg.present = true;
    useArg.value = 2;
    enabled = false;
    assert(DC::read(&controller, &enabled) && enabled);
    assert(propertyState.receiver == &provider);

    reset();
    propertyState.value = &property;
    providerState.provider = &provider;
    useArg.mutateWhenMissing = true; // A failed parse must preserve default 1.
    enabled = false;
    assert(DC::read(&controller, &enabled) && enabled);
    assert(propertyState.receiver == &controller && providerState.calls == 0);
}

static void propertyWordsLengthsTypesAndRelease() {
    const uint32_t words[] = {0U, 1U, 2U, 3U, 0x80000000U, 0xffffffffU,
                              0x89abcdefU, 0x76543210U};
    for (uint32_t word : words) {
        for (size_t length : {size_t(4), size_t(5), size_t(8)}) {
            reset();
            IOService controller;
            uint8_t bytes[8] {};
            memcpy(bytes, &word, sizeof(word));
            OSData property(bytes, length);
            propertyState.value = &property;
            bool enabled = !((word & 1U) != 0);
            assert(DC::read(&controller, &enabled));
            assert(enabled == ((word & 1U) != 0));
            assert(property.retainCalls == 1 && property.releaseCalls == 1);
        }
    }

    for (size_t length : {size_t(0), size_t(1), size_t(2), size_t(3)}) {
        reset();
        IOService controller;
        uint8_t bytes[4] {1, 0, 0, 0};
        OSData property(bytes, length);
        propertyState.value = &property;
        bool enabled = true;
        assert(DC::read(&controller, &enabled));
        assert(!enabled); // Invalid property starts from the native false default.
        assert(property.calls_ == 1 && property.lastStart_ == 0 && property.lastLength_ == 4);
        assert(property.retainCalls == 1 && property.releaseCalls == 1);
    }

    reset();
    IOService controller;
    OSObject wrongType;
    propertyState.value = &wrongType;
    bool enabled = true;
    assert(DC::read(&controller, &enabled));
    assert(!enabled);
    assert(wrongType.retainCalls == 1 && wrongType.releaseCalls == 1);
}

static void missingPropertyDefaultsAndOverrideSemantics() {
    reset();
    IOService controller;
    propertyState.value = nullptr;
    bool enabled = true;
    assert(DC::read(&controller, &enabled));
    assert(!enabled); // A property miss is a valid disabled base value.

    reset();
    propertyState.value = nullptr;
    overrideArg.present = true;
    overrideArg.value = 1;
    enabled = false;
    assert(DC::read(&controller, &enabled));
    assert(enabled); // Present override can enable after a property miss.

    reset();
    const uint32_t word = 1;
    OSData property(reinterpret_cast<const uint8_t *>(&word), sizeof(word));
    propertyState.value = &property;
    overrideArg.present = true;
    overrideArg.value = 2;
    enabled = false;
    assert(DC::read(&controller, &enabled));
    assert(!enabled); // Override replaces only bit 0.

    reset();
    propertyState.value = &property;
    overrideArg.mutateWhenMissing = true; // Failed parse scribbles only its local buffer.
    enabled = false;
    assert(DC::read(&controller, &enabled));
    assert(enabled); // The valid property bit survives a failed override parse.
}

static void nullInputsAndNullRootLeaveOutputUntouched() {
    reset();
    bool enabled = true;
    assert(!DC::read(nullptr, &enabled));
    assert(enabled && useReads == 0 && overrideReads == 0 && propertyState.calls == 0);
    IOService controller;
    assert(!DC::read(&controller, nullptr));
    assert(useReads == 0 && overrideReads == 0 && propertyState.calls == 0);

    // A parsed non-1 source selector with a null provider is a null root.
    useArg.present = true;
    useArg.value = 0;
    overrideArg.present = true;
    overrideArg.value = 1;
    enabled = true;
    assert(!DC::read(&controller, &enabled));
    assert(enabled);
    assert(providerState.calls == 1 && propertyState.calls == 0);
    assert(overrideReads == 0); // Null root exits before the enhanced override.
}

int main() {
    validRootAndExactOptions();
    sourceBootArgChoosesControllerOrProvider();
    propertyWordsLengthsTypesAndRelease();
    missingPropertyDefaultsAndOverrideSemantics();
    nullInputsAndNullRootLeaveOutputUntouched();
}
'''


CALLBACK_HARNESS_PREFIX = r'''
#include <assert.h>
#include <stdint.h>
#include <string.h>

class IOService {
public:
    bool inactive = false;
    bool pci = false;
    IOService *provider = nullptr;
    unsigned inactiveCalls = 0;
    unsigned providerCalls = 0;
    unsigned metaCastCalls = 0;
    const char *lastMetaCastName = nullptr;

    bool isInactive() {
        ++inactiveCalls;
        return inactive;
    }
    IOService *getProvider() {
        ++providerCalls;
        return provider;
    }
    void *metaCast(const char *name) {
        ++metaCastCalls;
        lastMetaCastName = name;
        return pci && name && !strcmp(name, "IOPCIDevice") ? this : nullptr;
    }
};

struct ReaderState {
    unsigned calls = 0;
    IOService *controller = nullptr;
    bool *output = nullptr;
    bool result = false;
    bool writeOutput = false;
    bool value = false;
};
static ReaderState readerState;

namespace LegacyWiFi { namespace DisassociateConfig {
bool read(IOService *controller, bool *enabled) {
    ++readerState.calls;
    readerState.controller = controller;
    readerState.output = enabled;
    if (readerState.writeOutput && enabled) *enabled = readerState.value;
    return readerState.result;
}
} }

namespace LegacyWiFi { namespace Installer { namespace {
'''

CALLBACK_HARNESS_SUFFIX = r'''
} // anonymous namespace

bool invokeEnhancedReasonConfiguration(void *controller, bool *enabled) {
    return enhancedReasonConfiguration(controller, enabled);
}
} }

static void resetReader() {
    readerState = ReaderState {};
}

static void rejectsUnqualifiedServicesWithoutReading() {
    resetReader();
    bool enabled = true;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(nullptr, &enabled));
    assert(enabled && readerState.calls == 0);

    IOService controller;
    controller.inactive = true;
    enabled = false;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(!enabled && readerState.calls == 0 && controller.providerCalls == 0);

    controller.inactive = false;
    enabled = true;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(enabled && readerState.calls == 0 && controller.providerCalls == 1);

    IOService provider;
    controller.provider = &provider;
    provider.inactive = true;
    enabled = false;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(!enabled && readerState.calls == 0 && provider.metaCastCalls == 0);

    provider.inactive = false;
    provider.pci = false;
    enabled = true;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(enabled && readerState.calls == 0 && provider.metaCastCalls == 1);
    assert(provider.lastMetaCastName && !strcmp(provider.lastMetaCastName, "IOPCIDevice"));
}

static void qualifiedPCIProviderForwardsReaderResultAndOutput() {
    IOService controller;
    IOService provider;
    controller.provider = &provider;
    provider.pci = true;

    resetReader();
    readerState.result = true;
    readerState.writeOutput = true;
    readerState.value = true;
    bool enabled = false;
    assert(LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(enabled && readerState.calls == 1 && readerState.controller == &controller &&
           readerState.output == &enabled);
    assert(provider.metaCastCalls == 1 && provider.lastMetaCastName &&
           !strcmp(provider.lastMetaCastName, "IOPCIDevice"));

    resetReader();
    readerState.result = true;
    readerState.writeOutput = true;
    readerState.value = false;
    enabled = true;
    assert(LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(!enabled && readerState.calls == 1 && readerState.controller == &controller &&
           readerState.output == &enabled);

    resetReader();
    readerState.result = false;
    enabled = true;
    assert(!LegacyWiFi::Installer::invokeEnhancedReasonConfiguration(&controller, &enabled));
    assert(enabled && readerState.calls == 1 && readerState.controller == &controller &&
           readerState.output == &enabled);
}

int main() {
    rejectsUnqualifiedServicesWithoutReading();
    qualifiedPCIProviderForwardsReaderResultAndOutput();
}
'''


def extract_cpp_function(source: str, signature: str) -> str:
    """Extract one complete function body from the production source text."""
    start = source.index(signature)
    opening = source.index("{", start + len(signature))
    depth = 0
    state = "code"
    escaped = False
    index = opening
    while index < len(source):
        char = source[index]
        next_char = source[index + 1] if index + 1 < len(source) else ""
        if state == "line-comment":
            if char == "\n":
                state = "code"
        elif state == "block-comment":
            if char == "*" and next_char == "/":
                state = "code"
                index += 1
        elif state in ("string", "character"):
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif (state == "string" and char == '"') or \
                    (state == "character" and char == "'"):
                state = "code"
        elif char == "/" and next_char == "/":
            state = "line-comment"
            index += 1
        elif char == "/" and next_char == "*":
            state = "block-comment"
            index += 1
        elif char == '"':
            state = "string"
        elif char == "'":
            state = "character"
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
        index += 1
    raise ValueError(f"unterminated production function: {signature}")


def production_callback_harness() -> str:
    source = INSTALL_SOURCE.read_text()
    callback = extract_cpp_function(
        source, "bool enhancedReasonConfiguration(void *controller,bool *enabled)")
    return CALLBACK_HARNESS_PREFIX + callback + CALLBACK_HARNESS_SUFFIX


class DisassociateConfigTests(unittest.TestCase):
    def test_actual_cpp_with_iokit_mock_tracks_semantics(self):
        clang = subprocess.run(["xcrun", "--find", "clang++"], check=True,
                               capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="disassociate-config-") as tmp:
            root = Path(tmp)
            for name, contents in MOCK_HEADERS.items():
                path = root / "mock" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(contents)
            harness = root / "harness.cpp"
            harness.write_text(HARNESS)
            binary = root / "test"
            subprocess.run([clang, "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            "-I", str(root / "mock"), "-I", str(PROJECT / "src"),
                            str(SOURCE), str(harness), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)

    def test_cpp_parses_against_kernel_sdk(self):
        sdk = subprocess.run(["xcrun", "--sdk", "macosx", "--show-sdk-path"],
                             check=True, capture_output=True, text=True).stdout.strip()
        headers = Path(sdk) / "System/Library/Frameworks/Kernel.framework/Headers"
        self.assertTrue(headers.is_dir(), f"missing Kernel.framework headers: {headers}")
        subprocess.run(["xcrun", "--sdk", "macosx", "clang++", "-std=gnu++17",
                        "-fapple-kext", "-fsyntax-only", "-I", str(headers),
                        "-I", str(PROJECT / "src"), "-isysroot", sdk, str(SOURCE)],
                       check=True, capture_output=True, timeout=30)

    def test_actual_install_callback_requires_active_pci_provider_and_forwards_reader(self):
        clang = subprocess.run(["xcrun", "--find", "clang++"], check=True,
                               capture_output=True, text=True).stdout.strip()
        with tempfile.TemporaryDirectory(prefix="disassociate-config-callback-") as tmp:
            root = Path(tmp)
            harness = root / "callback_harness.cpp"
            harness.write_text(production_callback_harness())
            binary = root / "test"
            subprocess.run([clang, "-std=c++14", "-Wall", "-Wextra", "-Werror",
                            "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                            str(harness), "-o", str(binary)],
                           check=True, capture_output=True, timeout=30)
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
