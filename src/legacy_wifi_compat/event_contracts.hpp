// Narrow event and scan-completion contract for the pinned El Capitan
// IO80211 provider and its two audited Broadcom controller kexts.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_EVENT_CONTRACTS_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_EVENT_CONTRACTS_HPP

#include <stddef.h>
#include <stdint.h>

namespace LegacyWiFi {
namespace EventContracts {

constexpr size_t MachHeader64Size = 32;
constexpr size_t MachHeaderCommandLimit = 8192;
constexpr size_t KernelEventHeaderSize = 24;
constexpr size_t KernelEventFilterSize = 12;
constexpr size_t InterfaceNameSize = 16;
constexpr size_t MaximumEventPayloadSize = 0x7f0;
constexpr uint32_t NativeEventVendor = 1;
constexpr uint32_t NativeEventClass = 6;
constexpr uint32_t NativeEventSubclass = 1;
constexpr uint32_t SSIDChangedEventCode = 2;
constexpr uint32_t BSSIDChangedEventCode = 3;
constexpr uint32_t RSNHandshakeCompleteEventCode = 20;
constexpr uint32_t ScanDoneEventCode = 10;
constexpr uint32_t ScanCacheUpdatedEventCode = 15;
constexpr uint32_t LinkStateEventCode = 4;
// These TLV IDs are kept as wire identifiers. Code 4's BSD payload is opaque;
// its length does not identify which TLV produced it.
constexpr uint32_t LinkTLVType4 = 4;
constexpr uint32_t LinkTLVInterfaceState = 13;
constexpr uint32_t LinkTLVLinkState = 14;
constexpr size_t LinkTLVHeaderSize = 8;
// Bridge admission ceiling for a TLV wrapper, not a provider ABI limit.
constexpr size_t MaximumLinkTLVInputSize = MaximumEventPayloadSize + LinkTLVHeaderSize;
constexpr size_t NativeScanDoneCapabilityIndex = 46;

struct LinkEventProjection {
    const uint8_t *payload = nullptr;
    size_t payloadSize = 0;
};

inline uint32_t readLinkTLVWord(const uint8_t *bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

// Mirrors only the pinned provider's code-4 selection order: the first type 4
// wins, otherwise the first type 13, otherwise the first type 14. Validate the
// complete list before projecting its opaque value bytes.
inline bool projectLinkEventPayload(const uint8_t *tlvs, size_t tlvSize,
                                    LinkEventProjection *out) {
    if (!out) return false;
    *out = {};
    const uintptr_t base = reinterpret_cast<uintptr_t>(tlvs);
    if (!tlvs || tlvSize < LinkTLVHeaderSize ||
        tlvSize > MaximumLinkTLVInputSize ||
        tlvSize > static_cast<size_t>(UINTPTR_MAX - base)) return false;

    struct Candidate {
        size_t valueOffset = 0;
        size_t valueSize = 0;
        bool found = false;
    } type4, type13, type14;

    size_t offset = 0;
    while (offset < tlvSize) {
        if (offset > tlvSize || tlvSize - offset < LinkTLVHeaderSize) return false;
        const uint8_t *header = tlvs + offset;
        const uint32_t type = readLinkTLVWord(header);
        const uint32_t valueSize32 = readLinkTLVWord(header + 4);
        const size_t remaining = tlvSize - offset - LinkTLVHeaderSize;
        if (static_cast<size_t>(valueSize32) > remaining) return false;

        Candidate *candidate = nullptr;
        if (type == LinkTLVType4) candidate = &type4;
        else if (type == LinkTLVInterfaceState) candidate = &type13;
        else if (type == LinkTLVLinkState) candidate = &type14;
        if (candidate && !candidate->found) {
            candidate->valueOffset = offset + LinkTLVHeaderSize;
            candidate->valueSize = static_cast<size_t>(valueSize32);
            candidate->found = true;
        }

        offset += LinkTLVHeaderSize + static_cast<size_t>(valueSize32);
    }
    if (offset != tlvSize) return false;

    const Candidate *selected = type4.found ? &type4
        : type13.found ? &type13
        : type14.found ? &type14 : nullptr;
    if (!selected || selected->valueSize > MaximumEventPayloadSize) return false;
    out->payload = tlvs + selected->valueOffset;
    out->payloadSize = selected->valueSize;
    return true;
}

// `mappedHeader` must point at the loaded Mach-O header of the image, with
// the whole mapped image contiguous for `mappedSize` bytes. The helper reads
// LC_UUID and __TEXT layout from that header; it never trusts an external UUID.
struct LoadedImage {
    const uint8_t *mappedHeader = nullptr;
    size_t mappedSize = 0;
};

// Addresses are already-resolved symbols in the currently loaded image.
// The verifier checks each against its pinned image-relative address.
struct ProviderSymbols {
    uintptr_t getBSDName = 0;
    uintptr_t postMessage = 0;
    uintptr_t postMessageBSD = 0;
    uintptr_t scanManagerScanDone = 0;
    uintptr_t kevPostMsg = 0;
};

enum class DriverKind : uint8_t {
    Broadcom4331,
    Broadcom43224,
};

struct DriverSymbols {
    uintptr_t scanDone = 0;
    uintptr_t scanComplete = 0;
};

// These names identify the driver families whose exact image UUIDs and scan
// callbacks are covered below. The callback does not claim AWDL support.
inline const char *controllerClassName(DriverKind kind) {
    return kind == DriverKind::Broadcom4331 ? "AirPort_Brcm4331" : "AirPort_Brcm43224";
}

inline const char *interfaceClassName(DriverKind kind) {
    return kind == DriverKind::Broadcom4331 ? "AirPort_Brcm4331_Interface"
                                             : "AirPort_Brcm43224Interface";
}

namespace Detail {

constexpr uint32_t MachMagic64 = 0xfeedfacf;
constexpr uint32_t CpuTypeX86_64 = 0x01000007;
constexpr uint32_t FileTypeKextBundle = 0x0b;
constexpr uint32_t LoadCommandSegment64 = 0x19;
constexpr uint32_t LoadCommandUUID = 0x1b;
constexpr size_t SegmentCommand64Size = 72;
constexpr size_t Section64Size = 80;
constexpr size_t UUIDCommandSize = 24;
constexpr uint32_t SegmentProtectionExecute = 0x4;
constexpr uint32_t SectionAttributePureInstructions = 0x80000000;

struct ParsedImage {
    uintptr_t base;
    size_t size;
    size_t textOffset;
    size_t textSize;
    const uint8_t *uuid;
};

inline uint32_t read32(const uint8_t *bytes) {
    return static_cast<uint32_t>(bytes[0]) |
           (static_cast<uint32_t>(bytes[1]) << 8) |
           (static_cast<uint32_t>(bytes[2]) << 16) |
           (static_cast<uint32_t>(bytes[3]) << 24);
}

inline uint64_t read64(const uint8_t *bytes) {
    return static_cast<uint64_t>(read32(bytes)) |
           (static_cast<uint64_t>(read32(bytes + 4)) << 32);
}

inline bool range(size_t imageSize, size_t offset, size_t count) {
    return offset <= imageSize && count <= imageSize - offset;
}

inline bool sameBytes(const uint8_t *left, const uint8_t *right, size_t count) {
    for (size_t index = 0; index < count; ++index) {
        if (left[index] != right[index]) return false;
    }
    return true;
}

inline bool sameLiteral(const uint8_t *bytes, size_t count, const char *literal,
                        size_t literalLength) {
    if (count != literalLength) return false;
    for (size_t index = 0; index < count; ++index) {
        if (bytes[index] != static_cast<uint8_t>(literal[index])) return false;
    }
    return true;
}

inline bool fixedName(const uint8_t *bytes, const char *literal, size_t literalLength) {
    for (size_t index = 0; index < 16; ++index) {
        const uint8_t expected = index < literalLength
            ? static_cast<uint8_t>(literal[index]) : 0;
        if (bytes[index] != expected) return false;
    }
    return true;
}

inline bool parseImage(const LoadedImage &image, ParsedImage &parsed) {
    if (!image.mappedHeader || image.mappedSize < MachHeader64Size) return false;
    const uint8_t *bytes = image.mappedHeader;
    const uintptr_t imageBase = reinterpret_cast<uintptr_t>(bytes);
    if (!imageBase || imageBase % 8 ||
        image.mappedSize > static_cast<size_t>(UINTPTR_MAX - imageBase)) return false;
    if (read32(bytes) != MachMagic64) return false;
    const uint32_t cpuType = read32(bytes + 4);
    const uint32_t fileType = read32(bytes + 12);
    const uint32_t commandCount = read32(bytes + 16);
    const uint32_t commandBytes = read32(bytes + 20);
    if (cpuType != CpuTypeX86_64 || fileType != FileTypeKextBundle ||
        commandCount == 0 || commandCount > 128 ||
        commandBytes > MachHeaderCommandLimit - MachHeader64Size ||
        commandCount > commandBytes / 8 ||
        !range(image.mappedSize, MachHeader64Size, commandBytes)) return false;

    const size_t commandsEnd = MachHeader64Size + commandBytes;
    size_t cursor = MachHeader64Size;
    bool foundText = false;
    bool foundCodeSection = false;
    bool foundUUID = false;
    uint64_t textSize = 0;
    uint64_t textOffset = 0;
    const uint8_t *uuid = nullptr;
    for (uint32_t index = 0; index < commandCount; ++index) {
        if (!range(commandsEnd, cursor, 8)) return false;
        const uint32_t command = read32(bytes + cursor);
        const uint32_t commandSize = read32(bytes + cursor + 4);
        if (commandSize < 8 || !range(commandsEnd, cursor, commandSize)) return false;
        if (command == LoadCommandSegment64) {
            if (commandSize < SegmentCommand64Size) return false;
            const uint8_t *segmentName = bytes + cursor + 8;
            if (fixedName(segmentName, "__TEXT", 6)) {
                const uint64_t vmAddress = read64(bytes + cursor + 24);
                const uint64_t vmSize = read64(bytes + cursor + 32);
                const uint64_t fileOffset = read64(bytes + cursor + 40);
                const uint64_t fileSize = read64(bytes + cursor + 48);
                const uint32_t maxProtection = read32(bytes + cursor + 56);
                const uint32_t initialProtection = read32(bytes + cursor + 60);
                const uint32_t sectionCount = read32(bytes + cursor + 64);
                const size_t available = commandSize - SegmentCommand64Size;
                if (foundText || sectionCount > available / Section64Size ||
                    available != static_cast<size_t>(sectionCount) * Section64Size ||
                    (vmAddress != 0 && vmAddress != static_cast<uint64_t>(imageBase)) ||
                    fileOffset != 0 || !vmSize || vmSize > image.mappedSize ||
                    fileSize > vmSize || fileSize > image.mappedSize ||
                    !(maxProtection & SegmentProtectionExecute) ||
                    !(initialProtection & SegmentProtectionExecute) ||
                    vmAddress > UINT64_MAX - vmSize) return false;
                textSize = vmSize;
                const uint8_t *sections = bytes + cursor + SegmentCommand64Size;
                for (uint32_t sectionIndex = 0; sectionIndex < sectionCount; ++sectionIndex) {
                    const uint8_t *section = sections + static_cast<size_t>(sectionIndex) * Section64Size;
                    const uint8_t *sectionName = section;
                    const uint8_t *sectionSegmentName = section + 16;
                    if (!fixedName(sectionName, "__text", 6)) continue;
                    if (foundCodeSection ||
                        !fixedName(sectionSegmentName, "__TEXT", 6))
                        return false;
                    const uint64_t sectionAddress = read64(section + 32);
                    const uint64_t sectionSize = read64(section + 40);
                    const uint32_t sectionFileOffset = read32(section + 48);
                    const uint32_t sectionFlags = read32(section + 64);
                    if (sectionAddress < vmAddress || !sectionSize ||
                        sectionAddress - vmAddress > vmSize ||
                        sectionSize > vmSize - (sectionAddress - vmAddress) ||
                        sectionAddress - vmAddress > fileSize ||
                        sectionSize > fileSize - (sectionAddress - vmAddress) ||
                        sectionAddress - vmAddress > image.mappedSize ||
                        sectionSize > image.mappedSize - static_cast<size_t>(sectionAddress - vmAddress) ||
                        sectionFileOffset != sectionAddress - vmAddress ||
                        !(sectionFlags & SectionAttributePureInstructions)) return false;
                    textOffset = sectionAddress - vmAddress;
                    textSize = sectionSize;
                    foundCodeSection = true;
                }
                foundText = true;
            }
        } else if (command == LoadCommandUUID) {
            if (foundUUID || commandSize != UUIDCommandSize) return false;
            uuid = bytes + cursor + 8;
            foundUUID = true;
        }
        cursor += commandSize;
    }
    if (cursor != commandsEnd || !foundText || !foundCodeSection || !foundUUID) return false;
    parsed = {imageBase, image.mappedSize, static_cast<size_t>(textOffset),
              static_cast<size_t>(textSize), uuid};
    return true;
}

inline bool uuidEquals(const ParsedImage &image, const uint8_t expected[16]) {
    return sameBytes(image.uuid, expected, 16);
}

inline bool symbolAt(const ParsedImage &image, uintptr_t address, size_t offset) {
    return address >= image.base && address - image.base == offset &&
           offset >= image.textOffset && offset - image.textOffset < image.textSize;
}

inline bool textRange(const ParsedImage &image, size_t offset, size_t count) {
    return offset >= image.textOffset &&
           range(image.textOffset + image.textSize, offset, count) &&
           range(image.size, offset, count);
}

inline const uint8_t *imageBytes(const ParsedImage &image) {
    return reinterpret_cast<const uint8_t *>(image.base);
}

inline bool maskedBytes(const ParsedImage &image, size_t offset, const uint8_t *expected,
                        size_t count, const size_t *mutableOffsets,
                        size_t mutableCount) {
    if (!textRange(image, offset, count)) return false;
    for (size_t index = 0; index < count; ++index) {
        bool mutableByte = false;
        for (size_t item = 0; item < mutableCount; ++item) {
            if (mutableOffsets[item] == index) {
                mutableByte = true;
                break;
            }
        }
        if (!mutableByte && imageBytes(image)[offset + index] != expected[index]) return false;
    }
    return true;
}

inline bool addAddress(uintptr_t base, size_t offset, uintptr_t &result) {
    if (offset > static_cast<size_t>(UINTPTR_MAX - base)) return false;
    result = base + offset;
    return true;
}

inline bool relativeTarget(const ParsedImage &image, size_t instructionOffset,
                           size_t displacementOffset, size_t displacementSize,
                           uintptr_t &target) {
    if ((displacementSize != 1 && displacementSize != 4) ||
        !textRange(image, instructionOffset, displacementOffset + displacementSize)) return false;
    const uint8_t *displacement = imageBytes(image) + instructionOffset + displacementOffset;
    int64_t delta = 0;
    if (displacementSize == 1) {
        delta = static_cast<int8_t>(displacement[0]);
    } else {
        delta = static_cast<int32_t>(read32(displacement));
    }
    uintptr_t origin = 0;
    if (!addAddress(image.base, instructionOffset + displacementOffset + displacementSize, origin)) {
        return false;
    }
    if (delta < 0) {
        const uintptr_t magnitude = static_cast<uintptr_t>(-delta);
        if (origin < magnitude) return false;
        target = origin - magnitude;
    } else {
        const uintptr_t magnitude = static_cast<uintptr_t>(delta);
        if (magnitude > UINTPTR_MAX - origin) return false;
        target = origin + magnitude;
    }
    return true;
}

inline bool callTargetIs(const ParsedImage &image, size_t instructionOffset,
                         uintptr_t expectedTarget) {
    if (!textRange(image, instructionOffset, 5) ||
        imageBytes(image)[instructionOffset] != 0xe8) return false;
    uintptr_t target = 0;
    return relativeTarget(image, instructionOffset, 1, 4, target) && target == expectedTarget;
}

inline bool jmpTargetIs(const ParsedImage &image, size_t instructionOffset,
                        uintptr_t expectedTarget) {
    if (!textRange(image, instructionOffset, 5) ||
        imageBytes(image)[instructionOffset] != 0xe9) return false;
    uintptr_t target = 0;
    return relativeTarget(image, instructionOffset, 1, 4, target) && target == expectedTarget;
}

inline bool shortBranchTargetIs(const ParsedImage &image, size_t instructionOffset,
                                uint8_t opcode, uintptr_t expectedTarget) {
    if (!textRange(image, instructionOffset, 2) ||
        imageBytes(image)[instructionOffset] != opcode) return false;
    uintptr_t target = 0;
    return relativeTarget(image, instructionOffset, 1, 1, target) && target == expectedTarget;
}

inline bool nearConditionalBranchTargetIs(const ParsedImage &image,
                                          size_t instructionOffset,
                                          uint8_t conditionOpcode,
                                          uintptr_t expectedTarget) {
    if (!textRange(image, instructionOffset, 6) ||
        imageBytes(image)[instructionOffset] != 0x0f ||
        imageBytes(image)[instructionOffset + 1] != conditionOpcode) return false;
    uintptr_t target = 0;
    return relativeTarget(image, instructionOffset, 2, 4, target) &&
           target == expectedTarget;
}

} // namespace Detail

inline bool matchesNativeWifiFilter(const uint8_t *filter, size_t size) {
    return filter && size == KernelEventFilterSize &&
           Detail::read32(filter) == NativeEventVendor &&
           Detail::read32(filter + 4) == NativeEventClass &&
           Detail::read32(filter + 8) == NativeEventSubclass;
}

enum class EventKind : uint8_t {
    Malformed,
    Foreign,
    UnknownNative,
    SSIDChanged,
    BSSIDChanged,
    RSNHandshakeComplete,
    ScanDone,
    ScanCacheUpdated,
    LinkState,
};

struct EventView {
    EventKind kind = EventKind::Malformed;
    uint32_t eventCode = 0;
    const uint8_t *interfaceName = nullptr;
    const uint8_t *payload = nullptr;
    size_t payloadSize = 0;
};

inline EventKind inspectNativeEvent(const uint8_t *packet, size_t packetSize,
                                    const char *expectedInterface,
                                    EventView &view) {
    view = {};
    if (!packet || packetSize < KernelEventHeaderSize + InterfaceNameSize ||
        packetSize > KernelEventHeaderSize + InterfaceNameSize + MaximumEventPayloadSize ||
        Detail::read32(packet) != packetSize) return view.kind;
    const uint32_t vendor = Detail::read32(packet + 4);
    const uint32_t eventClass = Detail::read32(packet + 8);
    const uint32_t eventSubclass = Detail::read32(packet + 12);
    if (vendor != NativeEventVendor || eventClass != NativeEventClass ||
        eventSubclass != NativeEventSubclass) {
        view.kind = EventKind::Foreign;
        return view.kind;
    }

    const uint8_t *name = packet + KernelEventHeaderSize;
    size_t nameLength = 0;
    while (nameLength < InterfaceNameSize && name[nameLength] != 0) ++nameLength;
    if (!nameLength || nameLength == InterfaceNameSize) return view.kind;
    if (expectedInterface) {
        size_t expectedLength = 0;
        while (expectedLength < InterfaceNameSize && expectedInterface[expectedLength] != '\0') {
            ++expectedLength;
        }
        if (!expectedLength || expectedLength == InterfaceNameSize ||
            expectedLength != nameLength ||
            !Detail::sameLiteral(name, nameLength, expectedInterface, expectedLength)) {
            view.kind = EventKind::Foreign;
            return view.kind;
        }
    }

    const uint8_t *payload = name + InterfaceNameSize;
    const size_t payloadSize = packetSize - KernelEventHeaderSize - InterfaceNameSize;
    const uint32_t eventCode = Detail::read32(packet + 20);
    view.eventCode = eventCode;
    view.interfaceName = name;
    view.payload = payload;
    view.payloadSize = payloadSize;
    if (eventCode == ScanDoneEventCode) {
        view.kind = payloadSize == 0 ? EventKind::ScanDone : EventKind::Malformed;
    } else if (eventCode == ScanCacheUpdatedEventCode) {
        view.kind = payloadSize == 0 ? EventKind::ScanCacheUpdated : EventKind::Malformed;
    } else if (eventCode == LinkStateEventCode) {
        // The provider strips its input TLV envelope before the BSD event.
        // The wire therefore carries opaque value bytes, not a recoverable TLV ID.
        view.kind = EventKind::LinkState;
    } else if (eventCode == SSIDChangedEventCode && payloadSize == 0) {
        view.kind = EventKind::SSIDChanged;
    } else if (eventCode == BSSIDChangedEventCode && payloadSize == 0) {
        view.kind = EventKind::BSSIDChanged;
    } else if (eventCode == RSNHandshakeCompleteEventCode && payloadSize == 0) {
        view.kind = EventKind::RSNHandshakeComplete;
    } else {
        // Other body shapes remain generic native events. In particular,
        // modern consumers accept an optional 8-byte body for event 2.
        view.kind = EventKind::UnknownNative;
    }
    return view.kind;
}

inline bool verifyProvider(const LoadedImage &provider, const ProviderSymbols &symbols) {
    Detail::ParsedImage parsed{};
    static const uint8_t expectedUUID[16] = {
        0xb6, 0xa4, 0x3e, 0xdc, 0x47, 0xe9, 0x3d, 0xb8,
        0x98, 0x87, 0x81, 0x2d, 0x1c, 0x77, 0xf3, 0x8c
    };
    if (!Detail::parseImage(provider, parsed) || !Detail::uuidEquals(parsed, expectedUUID) ||
        !Detail::symbolAt(parsed, symbols.getBSDName, 0x5822e) ||
        !Detail::symbolAt(parsed, symbols.postMessage, 0x58358) ||
        !Detail::symbolAt(parsed, symbols.postMessageBSD, 0x5d993) ||
        !Detail::symbolAt(parsed, symbols.scanManagerScanDone, 0x61d9e) ||
        !Detail::symbolAt(parsed, symbols.kevPostMsg, 0x744d4)) return false;

    // Keep the dispatcher that reaches code 4 and the complete code-4 route
    // pinned. Code 3 leaves the low-code dispatcher through the code-4
    // comparison at 0x584ee; code 20 takes a separate path through the code-9
    // check at 0x58494 and the code-14 check at 0x58555. In the retained
    // IO80211ElCap binary these ranges contain only same-image relative
    // branches/calls and have no Mach-O external or local relocation entries,
    // so their relative bytes are invariant when loaded.
    // The call targets below are decoded against independent pinned offsets;
    // no external zero-addend is treated as a loaded call destination.
    static const uint8_t postMessageEntry[0x1d] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0x48,
        0x83,0xec,0x40,0x41,0x89,0xf7,0x49,0x89,0xfe,0x48,0x89,0x55,
        0xc8,0x48,0x89,0x4d,0xc0
    };
    static const uint8_t messageDispatcher[0x24] = {
        0x41,0x83,0xff,0x47,0x7f,0x50,0x41,0x83,0xff,0x1f,0x0f,0x8f,
        0x91,0x00,0x00,0x00,0x41,0x83,0xff,0x08,0x0f,0x8f,0x05,0x01,
        0x00,0x00,0x41,0x83,0xff,0x02,0x0f,0x85,0x55,0x01,0x00,0x00
    };
    static const uint8_t code2EmptyPayloadRoute[9] = {
        0x48,0x85,0xc9,0x0f,0x84,0x67,0x03,0x00,0x00
    };
    static const uint8_t code4Unwrap[0x67] = {
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
    static const uint8_t code20Not9Dispatch[10] = {
        0x41,0x83,0xff,0x09,0x0f,0x85,0xb7,0x00,0x00,0x00
    };
    static const uint8_t code20Not14Route[10] = {
        0x41,0x83,0xff,0x0e,0x0f,0x85,0xaa,0x01,0x00,0x00
    };
    static const uint8_t type14Result[12] = {
        0xe8,0x4c,0xfc,0xff,0xff,0x3d,0xf0,0x02,0x00,0xe0,0x75,0x64
    };
    if (!Detail::symbolAt(parsed, parsed.base + 0x582ea, 0x582ea) ||
        !Detail::symbolAt(parsed, parsed.base + 0x6b250, 0x6b250) ||
        !Detail::maskedBytes(parsed, 0x58358, postMessageEntry,
                             sizeof(postMessageEntry), nullptr, 0) ||
        !Detail::maskedBytes(parsed, 0x58375, messageDispatcher,
                             sizeof(messageDispatcher), nullptr, 0) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x58389, 0x8f,
                                               parsed.base + 0x58494) ||
        !Detail::maskedBytes(parsed, 0x58399, code2EmptyPayloadRoute,
                             sizeof(code2EmptyPayloadRoute), nullptr, 0) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x58393, 0x85,
                                               parsed.base + 0x584ee) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x5839c, 0x84,
                                               parsed.base + 0x58709) ||
        !Detail::maskedBytes(parsed, 0x584ee, code4Unwrap,
                             sizeof(code4Unwrap), nullptr, 0) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x584f2, 0x85,
                                               parsed.base + 0x58709) ||
        !Detail::maskedBytes(parsed, 0x58494, code20Not9Dispatch,
                             sizeof(code20Not9Dispatch), nullptr, 0) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x58498, 0x85,
                                               parsed.base + 0x58555) ||
        !Detail::maskedBytes(parsed, 0x58555, code20Not14Route,
                             sizeof(code20Not14Route), nullptr, 0) ||
        !Detail::nearConditionalBranchTargetIs(parsed, 0x58559, 0x85,
                                               parsed.base + 0x58709) ||
        !Detail::callTargetIs(parsed, 0x5850a, parsed.base + 0x6b250) ||
        !Detail::callTargetIs(parsed, 0x5851c, parsed.base + 0x582ea) ||
        !Detail::callTargetIs(parsed, 0x58536, parsed.base + 0x582ea) ||
        !Detail::maskedBytes(parsed, 0x58699, type14Result,
                             sizeof(type14Result), nullptr, 0) ||
        !Detail::callTargetIs(parsed, 0x58699, parsed.base + 0x582ea)) return false;

    // Pin the native BSD helper's entry checks as well as its sender body:
    // this includes the zero-length/null-pointer split and its 0x7f0 bound.
    // The retained provider has no relocation entries in this prologue.
    static const uint8_t bsdHelperPrelude[0x27] = {
        0x55,0x48,0x89,0xe5,0x48,0x83,0xec,0x60,0x48,0x85,0xc9,0x74,0x15,
        0x83,0xfe,0x3a,0x74,0x58,0x48,0x85,0xd2,0x74,0x53,0x48,0x81,0xf9,
        0xf0,0x07,0x00,0x00,0x76,0x07,0xeb,0x48,0x83,0xfe,0x3a,0x74,0x43
    };
    if (!Detail::maskedBytes(parsed, 0x5d993, bsdHelperPrelude,
                             sizeof(bsdHelperPrelude), nullptr, 0)) return false;

    // Full body of IO80211Interface::setDataPointerAndLengthForMessageType.
    // It strips the 8-byte TLV header, installs the encoded value length, and
    // searches past nonmatching TLVs. No bytes in this method carry loader
    // relocations in the pinned Mach-O.
    static const uint8_t setDataPointerAndLengthForMessageType[0x55] = {
        0x55,0x48,0x89,0xe5,0x4c,0x8b,0x0a,0xb8,0xf0,0x02,0x00,0xe0,
        0x4d,0x85,0xc9,0x74,0x42,0x4c,0x8b,0x01,0xb8,0xf0,0x02,0x00,
        0xe0,0x31,0xff,0x49,0x83,0xf8,0x08,0x72,0x32,0x4c,0x8d,0x57,
        0x08,0x41,0x39,0x34,0x39,0x75,0x19,0x4f,0x8d,0x1c,0x11,0x4c,
        0x89,0x1a,0x42,0x8b,0x7c,0x0f,0x04,0x48,0x89,0x39,0x31,0xc0,
        0x49,0x89,0xf8,0x4d,0x89,0xd9,0xeb,0x05,0x42,0x8b,0x7c,0x0f,
        0x04,0x89,0xff,0x4c,0x01,0xd7,0x4c,0x39,0xc7,0x72,0xce,0x5d,
        0xc3
    };
    if (!Detail::maskedBytes(parsed, 0x582ea,
                             setDataPointerAndLengthForMessageType,
                             sizeof(setDataPointerAndLengthForMessageType),
                             nullptr, 0)) return false;

    // IO80211Interface::postMessage's native BSD fallback. Its two call
    // targets are checked after masking only their link-time displacements.
    static const uint8_t fallback[33] = {
        0x4c,0x89,0xf7,0xe8,0,0,0,0,0x4c,0x8b,0x65,0xc8,
        0x48,0x8b,0x5d,0xc0,0x48,0x89,0xc7,0x44,0x89,0xfe,
        0x4c,0x89,0xe2,0x48,0x89,0xd9,0xe8,0,0,0,0
    };
    static const size_t fallbackMasks[] = {4,5,6,7,29,30,31,32};
    if (!Detail::maskedBytes(parsed, 0x5875a, fallback, sizeof(fallback),
                             fallbackMasks, sizeof(fallbackMasks)/sizeof(fallbackMasks[0])) ||
        !Detail::callTargetIs(parsed, 0x5875d, symbols.getBSDName) ||
        !Detail::callTargetIs(parsed, 0x58776, symbols.postMessageBSD)) return false;

    // The provider chooses between its native data-path route and the BSD
    // fallback by testing the interface's peer-manager field at +0x148. The
    // short branch must still land on the verified fallback body above.
    static const uint8_t routeSelect[10] = {
        0x49,0x83,0xbe,0x48,0x01,0,0,0,0x74,0
    };
    static const size_t routeSelectMasks[] = {9};
    if (!Detail::maskedBytes(parsed, 0x58709, routeSelect, sizeof(routeSelect),
                             routeSelectMasks, sizeof(routeSelectMasks)/sizeof(routeSelectMasks[0])) ||
        !Detail::shortBranchTargetIs(parsed, 0x58711, 0x74, parsed.base + 0x5875a)) return false;

    static const uint8_t code15[19] = {
        0x49,0x8b,0x7c,0x24,0x58,0xbe,0x0f,0,0,0,0x31,0xd2,0x31,0xc9,0xe8,0,0,0,0
    };
    static const size_t code15Masks[] = {15,16,17,18};
    if (!Detail::maskedBytes(parsed, 0x61fbc, code15, sizeof(code15),
                             code15Masks, sizeof(code15Masks)/sizeof(code15Masks[0])) ||
        !Detail::callTargetIs(parsed, 0x61fca, symbols.postMessage)) return false;

    // The BSD sender constructs vendor/class/subclass 1/6/1, stores the
    // event code, starts event data with the 16-byte BSD name, permits an
    // empty payload, and forwards to IO80211QueueCall::kev_post_msg.
    static const uint8_t sender[0x43] = {
        0xc7,0x45,0xa0,0x01,0,0,0,0xc7,0x45,0xa4,0x06,0,0,0,
        0xc7,0x45,0xa8,0x01,0,0,0,0x89,0x75,0xac,0xc7,0x45,0xb0,0x10,0,0,0,
        0x48,0x89,0x7d,0xb8,0x31,0xc0,0x48,0x85,0xc9,0x74,0x0d,0x48,0x89,0x55,
        0xc8,0xc7,0x45,0xd0,0,0,0,0,0x89,0xc8,0x89,0x45,0xc0,0x48,0x8d,0x7d,
        0xa0,0xe8,0,0,0,0
    };
    static const size_t senderMasks[] = {63,64,65,66};
    return Detail::maskedBytes(parsed, 0x5d9ba, sender, sizeof(sender),
                               senderMasks, sizeof(senderMasks)/sizeof(senderMasks[0])) &&
           Detail::callTargetIs(parsed, 0x5d9f8, symbols.kevPostMsg);
}

inline bool verifyDriver(const LoadedImage &driver, DriverKind kind,
                         const DriverSymbols &symbols,
                         const LoadedImage &providerImage,
                         const ProviderSymbols &providerSymbols) {
    Detail::ParsedImage parsed{};
    Detail::ParsedImage provider{};
    static const uint8_t uuid4331[16] = {
        0x59,0xc1,0xf2,0xa3,0xd3,0xb8,0x3c,0x3e,
        0x8d,0x7d,0x3e,0x58,0xcb,0xd5,0x45,0x00
    };
    static const uint8_t uuid43224[16] = {
        0x6f,0x07,0x4d,0x2e,0xe7,0xe8,0x32,0x7b,
        0xac,0x63,0xf5,0x04,0xb7,0x36,0x7b,0xa4
    };
    if (!Detail::parseImage(driver, parsed) ||
        !Detail::parseImage(providerImage, provider) ||
        !Detail::symbolAt(provider, providerSymbols.postMessage, 0x58358) ||
        !Detail::symbolAt(parsed, symbols.scanDone,
                          kind == DriverKind::Broadcom4331 ? 0xd350 : 0x95da) ||
        !Detail::symbolAt(parsed, symbols.scanComplete,
                          kind == DriverKind::Broadcom4331 ? 0xd202 : 0x94f6)) return false;

    if (kind == DriverKind::Broadcom4331) {
        if (!Detail::uuidEquals(parsed, uuid4331)) return false;
        static const uint8_t scanDone[0x4c] = {
            0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0x83,0xfe,0x10,0x74,0,
            0x48,0x8b,0x83,0x68,0x04,0,0,0x48,0x8b,0xb0,0x58,0x08,0,0,
            0x48,0x89,0xdf,0xe8,0,0,0,0,0x48,0x8b,0x03,0x48,0x89,0xdf,0xff,
            0x90,0x88,0x0c,0,0,0x48,0x85,0xc0,0x74,0,0xbe,0x0a,0,0,0,
            0x31,0xd2,0x31,0xc9,0x48,0x89,0xc7,0x48,0x83,0xc4,0x08,0x5b,0x5d,
            0xe9,0,0,0,0
        };
        static const size_t mutableOffsets[] = {13,32,33,34,35,52,72,73,74,75};
        return Detail::maskedBytes(parsed, 0xd350, scanDone, sizeof(scanDone),
                                   mutableOffsets, sizeof(mutableOffsets)/sizeof(mutableOffsets[0])) &&
               Detail::shortBranchTargetIs(parsed, 0xd35c, 0x74,
                                           parsed.base + 0xd39c) &&
               Detail::shortBranchTargetIs(parsed, 0xd383, 0x74,
                                           parsed.base + 0xd39c) &&
               Detail::callTargetIs(parsed, 0xd36f, symbols.scanComplete) &&
               Detail::jmpTargetIs(parsed, 0xd397, providerSymbols.postMessage);
    }

    if (kind == DriverKind::Broadcom43224) {
        if (!Detail::uuidEquals(parsed, uuid43224)) return false;
        static const uint8_t scanDone[0x44] = {
            0x55,0x48,0x89,0xe5,0x53,0x50,0x48,0x89,0xfb,0x48,0x8b,0xb3,0x18,0x04,
            0,0,0x48,0x81,0xc6,0xc8,0x21,0,0,0xe8,0,0,0,0,0x48,0x8b,0x03,0x48,
            0x89,0xdf,0xff,0x90,0x88,0x0c,0,0,0x48,0x85,0xc0,0x74,0,0xbe,0x0a,
            0,0,0,0x31,0xd2,0x31,0xc9,0x48,0x89,0xc7,0x48,0x83,0xc4,0x08,0x5b,
            0x5d,0xe9,0,0,0,0
        };
        static const size_t mutableOffsets[] = {24,25,26,27,44,64,65,66,67};
        return Detail::maskedBytes(parsed, 0x95da, scanDone, sizeof(scanDone),
                                  mutableOffsets, sizeof(mutableOffsets)/sizeof(mutableOffsets[0])) &&
               Detail::callTargetIs(parsed, 0x95f1, symbols.scanComplete) &&
               Detail::shortBranchTargetIs(parsed, 0x9605, 0x74,
                                           parsed.base + 0x961e) &&
               Detail::jmpTargetIs(parsed, 0x9619, providerSymbols.postMessage);
    }
    return false;
}

inline bool mayAdvertiseCapability46(const LoadedImage &provider,
                                     const ProviderSymbols &providerSymbols,
                                     const LoadedImage &driver, DriverKind kind,
                                     const DriverSymbols &driverSymbols) {
    return verifyProvider(provider, providerSymbols) &&
           verifyDriver(driver, kind, driverSymbols, provider, providerSymbols);
}

} // namespace EventContracts
} // namespace LegacyWiFi

#endif
