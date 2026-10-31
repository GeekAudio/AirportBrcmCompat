// Portable structural contract for the public IONetworkInterface if_ioctl
// callback and its initIfnetParams registration. The caller must supply a
// bounded view of a live mapped Mach-O image and independently resolved symbol
// addresses for the two imported calls. This code never invokes either target.
#ifndef PRIVATE_MAC_COMPAT_NETWORK_CALLBACK_CONTRACT_HPP
#define PRIVATE_MAC_COMPAT_NETWORK_CALLBACK_CONTRACT_HPP

#include <stddef.h>
#include <stdint.h>

namespace PrivateMAC { namespace NetworkCallbackContract {

static const uint32_t MachMagic64 = 0xfeedfacf;
static const uint32_t CpuTypeX86_64 = 0x01000007;
static const uint32_t MachFileTypeKextBundle = 0x0b;
static const uint32_t LoadCommandSegment64 = 0x19;
static const uint32_t VmProtExecute = 0x4;
static const uint32_t SectionAttributePureInstructions = 0x80000000U;
static const uint32_t SectionAttributeSomeInstructions = 0x00000400U;
static const size_t IfIoctlSize = 130;
static const size_t InitIfnetParamsSize = 0x64;
static const size_t CallbackBytes = IfIoctlSize;
static const size_t InitBytes = InitIfnetParamsSize;
static const size_t InitOutputLEAOffset = 0x2c;
static const size_t InitCallbackLEAOffset = 0x37;
static const size_t InitBpfLEAOffset = 0x42;
static const size_t InitDetachLEAOffset = 0x4d;
static const char IfIoctlSymbol[] = "__ZN18IONetworkInterface8if_ioctlEP7__ifnetmPv";
static const char InitIfnetParamsSymbol[] =
    "__ZN18IONetworkInterface15initIfnetParamsEP17ifnet_init_params";
static const char IfnetOutputSymbol[] =
    "__ZN18IONetworkInterface9if_outputEP7__ifnetP6__mbuf";
static const char IfnetSetBpfTapSymbol[] =
    "__ZN18IONetworkInterface14if_set_bpf_tapEP7__ifnetjPFiS1_P6__mbufE";
static const char IfnetDetachSymbol[] =
    "__ZN18IONetworkInterface9if_detachEP7__ifnet";

struct Targets {
    uintptr_t output;
    uintptr_t bpf;
    uintptr_t detach;

    constexpr Targets(uintptr_t outputAddress=0, uintptr_t bpfAddress=0,
                      uintptr_t detachAddress=0)
        : output(outputAddress), bpf(bpfAddress), detach(detachAddress) {}
};

struct ImageView {
    // mappedHeader points to the mapped MH_MAGIC_64 bytes. It may be a bounded
    // read-only mirror; runtimeHeaderAddress is the runtime VA corresponding
    // to byte zero. For a direct loaded image, these are the same address.
    const uint8_t *mappedHeader;
    size_t mappedSize;
    uintptr_t runtimeHeaderAddress;

    ImageView(const uint8_t *header=nullptr, size_t size=0,
              uintptr_t runtimeAddress=0)
        : mappedHeader(header), mappedSize(size),
          runtimeHeaderAddress(runtimeAddress) {}
};

namespace Detail {

static const size_t MachHeader64Size = 32;
static const size_t LoadCommandHeaderSize = 8;
static const size_t SegmentCommand64Size = 72;
static const size_t Section64Size = 80;
static const uint32_t MaximumLoadCommands = 256;
static const size_t MaximumLoadCommandBytes = 1024U * 1024U;

struct SegmentInfo {
    char name[16];
    uint64_t vmAddress;
    uint64_t vmSize;
    uint64_t fileSize;
    uint32_t initialProtection;
    uint32_t sectionCount;
    size_t commandOffset;
};

struct MachInfo {
    uint64_t textVMAddress;
    uint32_t commandCount;
};

inline uint32_t read32(const uint8_t *p) {
    return static_cast<uint32_t>(p[0]) |
           (static_cast<uint32_t>(p[1]) << 8) |
           (static_cast<uint32_t>(p[2]) << 16) |
           (static_cast<uint32_t>(p[3]) << 24);
}

inline uint64_t read64(const uint8_t *p) {
    return static_cast<uint64_t>(read32(p)) |
           (static_cast<uint64_t>(read32(p+4)) << 32);
}

inline bool checkedAddSize(size_t left, size_t right, size_t &out) {
    if (right > static_cast<size_t>(-1) - left) return false;
    out = left + right;
    return true;
}

inline bool checkedAddAddress(uintptr_t left, uintptr_t right,
                              uintptr_t &out) {
    if (right > static_cast<uintptr_t>(-1) - left) return false;
    out = left + right;
    return true;
}

inline bool checkedAddU64(uint64_t left, uint64_t right, uint64_t &out) {
    if (right > static_cast<uint64_t>(-1) - left) return false;
    out = left + right;
    return true;
}

inline bool sameName(const uint8_t *rawName, const char *name) {
    size_t i=0;
    while (i<16 && name[i] != '\0') {
        if (rawName[i] != static_cast<uint8_t>(name[i])) return false;
        ++i;
    }
    if (i==16 || name[i] != '\0') return false;
    for (; i<16; ++i) if (rawName[i] != 0) return false;
    return true;
}

inline bool checkedMappedOffset(const ImageView &image, uint64_t vmAddress,
                                uint64_t textVMAddress, size_t length,
                                size_t &offset) {
    if (vmAddress < textVMAddress) return false;
    const uint64_t delta = vmAddress - textVMAddress;
    if (delta > static_cast<uint64_t>(static_cast<size_t>(-1))) return false;
    offset = static_cast<size_t>(delta);
    if (offset > image.mappedSize || length > image.mappedSize - offset)
        return false;
    uintptr_t runtimeAddress=0;
    if (!checkedAddAddress(image.runtimeHeaderAddress,
                           static_cast<uintptr_t>(delta), runtimeAddress))
        return false;
    (void)runtimeAddress;
    return true;
}

inline bool parseImage(const ImageView &image, MachInfo &out) {
    if (!image.mappedHeader || image.mappedSize < MachHeader64Size ||
        image.runtimeHeaderAddress == 0) return false;
    const uint8_t *h=image.mappedHeader;
    if (read32(h) != MachMagic64 || read32(h+4) != CpuTypeX86_64 ||
        read32(h+12) != MachFileTypeKextBundle) return false;
    const uint32_t commandCount=read32(h+16);
    const uint32_t commandBytes=read32(h+20);
    if (commandCount == 0 || commandCount > MaximumLoadCommands ||
        commandBytes > MaximumLoadCommandBytes || (commandBytes & 7U) != 0)
        return false;
    size_t commandEnd=0;
    if (!checkedAddSize(MachHeader64Size, commandBytes, commandEnd) ||
        commandEnd > image.mappedSize) return false;

    size_t cursor=MachHeader64Size;
    uint32_t seen=0;
    bool haveText=false;
    uint64_t textVM=0;
    uint64_t textFileSize=0;
    uint64_t textVMEnd=0;
    while (seen < commandCount) {
        if (cursor > commandEnd || commandEnd-cursor < LoadCommandHeaderSize)
            return false;
        const uint8_t *cmd=h+cursor;
        const uint32_t kind=read32(cmd);
        const uint32_t size=read32(cmd+4);
        if (size < LoadCommandHeaderSize || (size & 7U) != 0 ||
            size > commandEnd-cursor)
            return false;
        if (kind == LoadCommandSegment64) {
            if (size < SegmentCommand64Size) return false;
            const uint32_t sections=read32(cmd+64);
            const size_t sectionBytes=size-SegmentCommand64Size;
            if (sectionBytes % Section64Size != 0 ||
                sections != sectionBytes/Section64Size)
                return false;
            if (sameName(cmd+8, "__TEXT")) {
                if (haveText) return false;
                textVM=read64(cmd+24);
                const uint64_t textVMSize=read64(cmd+32);
                textFileSize=read64(cmd+48);
                if (textVMSize == 0 || textFileSize > textVMSize ||
                    textFileSize < commandEnd ||
                    !checkedAddU64(textVM, textVMSize, textVMEnd)) return false;
                // The supplied mapped header is the __TEXT VM anchor; fileoff
                // is deliberately not used because fileset entries may carry
                // container-relative file offsets.
                haveText=true;
            }
        }
        cursor+=size;
        ++seen;
    }
    if (cursor != commandEnd || !haveText) return false;
    size_t headerMappedEnd=0;
    if (!checkedMappedOffset(image, textVM, textVM, commandEnd,
                             headerMappedEnd)) return false;
    uintptr_t headerRuntimeEnd=0;
    if (!checkedAddAddress(image.runtimeHeaderAddress,
                           static_cast<uintptr_t>(commandEnd),
                           headerRuntimeEnd)) return false;
    (void)headerRuntimeEnd;
    if (static_cast<uint64_t>(commandEnd) > textVMEnd-textVM) return false;

    out.textVMAddress=textVM;
    out.commandCount=commandCount;
    return true;
}

inline bool rangeInInstructionSection(const ImageView &image,
                                      const MachInfo &mach,
                                      const SegmentInfo &segment,
                                      uintptr_t address, size_t length) {
    const uint8_t *h=image.mappedHeader;
    size_t cursor=segment.commandOffset+SegmentCommand64Size;
    uintptr_t requestEnd=0;
    if (!checkedAddAddress(address, static_cast<uintptr_t>(length), requestEnd))
        return false;
    for (uint32_t i=0; i<segment.sectionCount; ++i) {
        const uint8_t *s=h+cursor;
        const uint64_t sectionAddress=read64(s+32);
        const uint64_t sectionSize=read64(s+40);
        const uint32_t flags=read32(s+64);
        const uint32_t instructionFlags=flags &
            (SectionAttributePureInstructions|SectionAttributeSomeInstructions);
        if (instructionFlags == 0 || sectionSize == 0) {
            cursor+=Section64Size;
            continue;
        }
        // The segment/section names in the Mach-O header are separate fields.
        // Require the section to belong to this executable segment; any
        // instruction-bearing section name is accepted.
        bool matchingSegmentName=true;
        for (size_t n=0; n<16; ++n)
            if (s[16+n] != static_cast<uint8_t>(segment.name[n]))
                matchingSegmentName=false;
        if (!matchingSegmentName) {
            cursor+=Section64Size;
            continue;
        }
        uint64_t sectionEnd=0;
        if (!checkedAddU64(sectionAddress, sectionSize, sectionEnd)) return false;
        uint64_t segmentFileEnd=0;
        if (!checkedAddU64(segment.vmAddress, segment.fileSize, segmentFileEnd))
            return false;
        uintptr_t sectionRuntime=0;
        uintptr_t sectionRuntimeEnd=0;
        if (sectionAddress < mach.textVMAddress) return false;
        const uint64_t delta=sectionAddress-mach.textVMAddress;
        if (delta > static_cast<uint64_t>(static_cast<uintptr_t>(-1)) ||
            !checkedAddAddress(image.runtimeHeaderAddress,
                               static_cast<uintptr_t>(delta), sectionRuntime) ||
            sectionSize > static_cast<uint64_t>(static_cast<uintptr_t>(-1)) ||
            !checkedAddAddress(sectionRuntime,
                               static_cast<uintptr_t>(sectionSize),
                               sectionRuntimeEnd)) return false;
        size_t mappedOffset=0;
        if (sectionSize > static_cast<uint64_t>(static_cast<size_t>(-1)) ||
            !checkedMappedOffset(image, sectionAddress, mach.textVMAddress,
                                 static_cast<size_t>(sectionSize), mappedOffset)) {
            cursor+=Section64Size;
            continue;
        }
        (void)mappedOffset;
        if (address >= sectionRuntime && requestEnd <= sectionRuntimeEnd &&
            address < requestEnd && sectionAddress >= segment.vmAddress &&
            sectionEnd <= segmentFileEnd)
            return true;
        cursor+=Section64Size;
    }
    return false;
}

inline bool resolveRel32(uintptr_t instructionAddress, size_t instructionSize,
                         const uint8_t *operand, uintptr_t &target) {
    uintptr_t next=0;
    if (!checkedAddAddress(instructionAddress,
                           static_cast<uintptr_t>(instructionSize), next))
        return false;
    const uint32_t raw=read32(operand);
    const int64_t displacement=(raw & 0x80000000U)
        ? static_cast<int64_t>(raw)-0x100000000LL
        : static_cast<int64_t>(raw);
    if (displacement >= 0) {
        return checkedAddAddress(next, static_cast<uintptr_t>(displacement), target);
    }
    const uintptr_t magnitude=static_cast<uintptr_t>(-displacement);
    if (next < magnitude) return false;
    target=next-magnitude;
    return true;
}

inline bool matchesBytes(const uint8_t *actual, const uint8_t *expected,
                         size_t begin, size_t end) {
    for (size_t i=begin; i<end; ++i)
        if (actual[i] != expected[i]) return false;
    return true;
}

} // namespace Detail

// Checks the bounded Mach-O load-command table, the unique __TEXT anchor, and
// that the requested bytes lie entirely inside an executable segment and an
// instruction-bearing section. Segment fileoff is not treated as a runtime VA.
inline bool containsExecutableRange(const ImageView &image, uintptr_t address,
                                    size_t length) {
    if (length == 0) return false;
    Detail::MachInfo mach={0,0};
    if (!Detail::parseImage(image, mach)) return false;
    uintptr_t requestEnd=0;
    if (!Detail::checkedAddAddress(address, static_cast<uintptr_t>(length),
                                   requestEnd)) return false;
    if (address < image.runtimeHeaderAddress) return false;

    size_t cursor=Detail::MachHeader64Size;
    for (uint32_t c=0; c<mach.commandCount; ++c) {
        const uint8_t *cmd=image.mappedHeader+cursor;
        const uint32_t kind=Detail::read32(cmd);
        const uint32_t commandSize=Detail::read32(cmd+4);
        if (kind == LoadCommandSegment64) {
            Detail::SegmentInfo segment;
            for (size_t i=0; i<16; ++i) segment.name[i]=static_cast<char>(cmd[8+i]);
            segment.vmAddress=Detail::read64(cmd+24);
            segment.vmSize=Detail::read64(cmd+32);
            segment.fileSize=Detail::read64(cmd+48);
            segment.initialProtection=Detail::read32(cmd+60);
            segment.sectionCount=Detail::read32(cmd+64);
            segment.commandOffset=cursor;
            uint64_t segmentVMEnd=0, segmentFileEnd=0;
            if (segment.vmSize == 0 || segment.fileSize > segment.vmSize ||
                !Detail::checkedAddU64(segment.vmAddress, segment.vmSize,
                                       segmentVMEnd) ||
                !Detail::checkedAddU64(segment.vmAddress, segment.fileSize,
                                       segmentFileEnd)) return false;
            if ((segment.initialProtection & VmProtExecute) != 0 &&
                segment.vmAddress >= mach.textVMAddress) {
                const uint64_t segmentDelta=segment.vmAddress-mach.textVMAddress;
                uintptr_t runtimeSegment=0, runtimeSegmentEnd=0,
                          runtimeSegmentFileEnd=0;
                if (segmentDelta <= static_cast<uint64_t>(static_cast<uintptr_t>(-1)) &&
                    Detail::checkedAddAddress(image.runtimeHeaderAddress,
                        static_cast<uintptr_t>(segmentDelta), runtimeSegment) &&
                    segment.vmSize <= static_cast<uint64_t>(static_cast<uintptr_t>(-1)) &&
                    Detail::checkedAddAddress(runtimeSegment,
                        static_cast<uintptr_t>(segment.vmSize), runtimeSegmentEnd) &&
                    segment.fileSize <= static_cast<uint64_t>(static_cast<uintptr_t>(-1)) &&
                    Detail::checkedAddAddress(runtimeSegment,
                        static_cast<uintptr_t>(segment.fileSize),
                        runtimeSegmentFileEnd) &&
                    address >= runtimeSegment && requestEnd <= runtimeSegmentEnd &&
                    address < requestEnd && requestEnd <= runtimeSegmentEnd &&
                    requestEnd <= runtimeSegmentFileEnd &&
                    Detail::rangeInInstructionSection(image, mach, segment,
                                                      address, length))
                    return true;
            }
        }
        cursor+=commandSize;
    }
    return false;
}

// Verifies the exact 130-byte if_ioctl body except for its two independently
// resolved import operands, plus the 100-byte initIfnetParams body except for
// four independently resolved LEA displacements. Function addresses and the
// three init targets must be resolved independently from the watched image.
inline bool verify(const ImageView &image, uintptr_t initAddress,
                   uintptr_t callbackAddress, uintptr_t ifnetSoftcTarget,
                   uintptr_t isInactiveTarget, const Targets &targets) {
    if (initAddress == 0 || callbackAddress == 0 || ifnetSoftcTarget == 0 ||
        isInactiveTarget == 0 || targets.output == 0 || targets.bpf == 0 ||
        targets.detach == 0) return false;
    if (!containsExecutableRange(image, initAddress, InitIfnetParamsSize) ||
        !containsExecutableRange(image, callbackAddress, IfIoctlSize) ||
        !containsExecutableRange(image, targets.output, 1) ||
        !containsExecutableRange(image, targets.bpf, 1) ||
        !containsExecutableRange(image, targets.detach, 1)) return false;
    const uintptr_t initOffsetAddress=initAddress-image.runtimeHeaderAddress;
    const uintptr_t callbackOffsetAddress=callbackAddress-image.runtimeHeaderAddress;
    if (initOffsetAddress > static_cast<uintptr_t>(image.mappedSize) ||
        InitIfnetParamsSize > image.mappedSize-static_cast<size_t>(initOffsetAddress) ||
        callbackOffsetAddress > static_cast<uintptr_t>(image.mappedSize) ||
        IfIoctlSize > image.mappedSize-static_cast<size_t>(callbackOffsetAddress))
        return false;
    const uint8_t *init=image.mappedHeader+static_cast<size_t>(initOffsetAddress);
    const uint8_t *callback=image.mappedHeader+static_cast<size_t>(callbackOffsetAddress);

    static const uint8_t expectedInit[InitIfnetParamsSize] = {
        0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x89,0xf3,0x49,0x89,0xfe,0x48,0x8b,0x07,
        0xff,0x90,0xa0,0x08,0x00,0x00,0x48,0x89,0x43,0x10,0x49,0x8b,0x86,0x08,0x01,0x00,
        0x00,0x8b,0x48,0x04,0x89,0x4b,0x20,0x8b,0x00,0x89,0x43,0x18,0x48,0x8d,0x05,0x00,
        0x00,0x00,0x00,0x48,0x89,0x43,0x28,0x48,0x8d,0x05,0x04,0x01,0x00,0x00,0x48,0x89,
        0x43,0x60,0x48,0x8d,0x05,0x00,0x00,0x00,0x00,0x48,0x89,0x43,0x68,0x48,0x8d,0x05,
        0x00,0x00,0x00,0x00,0x48,0x89,0x43,0x70,0x4c,0x89,0x73,0x58,0xb0,0x01,0x5b,0x41,
        0x5e,0x5d,0xc3,0x90
    };
    // The two four-byte operands at [0x18,0x1c) and [0x2e,0x32) are the only
    // bytes ignored in the if_ioctl comparison; each must independently
    // resolve to the supplied import address below.
    static const uint8_t expectedCallback[IfIoctlSize] = {
        0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50,0x48,0x89,
        0xd3,0x49,0x89,0xf7,0x49,0x89,0xfe,0xe8,0x00,0x00,0x00,0x00,0x41,0xbd,0x66,0x00,
        0x00,0x00,0x48,0x85,0xc0,0x74,0x49,0x49,0x89,0xc4,0x48,0x89,0xc7,0xe8,0x00,0x00,
        0x00,0x00,0x84,0xc0,0x75,0x3a,0x49,0x8b,0xb4,0x24,0x88,0x00,0x00,0x00,0x48,0x85,
        0xf6,0x74,0x27,0x49,0x8b,0x04,0x24,0x48,0x8b,0x80,0x60,0x09,0x00,0x00,0x4c,0x89,
        0xe7,0x4c,0x89,0xfa,0x4c,0x89,0xf1,0x49,0x89,0xd8,0x48,0x83,0xc4,0x08,0x5b,0x41,
        0x5c,0x41,0x5d,0x41,0x5e,0x41,0x5f,0x5d,0xff,0xe0,0x41,0xbd,0x16,0x00,0x00,0x00,
        0x44,0x89,0xe8,0x48,0x83,0xc4,0x08,0x5b,0x41,0x5c,0x41,0x5d,0x41,0x5e,0x41,0x5f,0x5d,0xc3
    };
    // Assert the bytes needed for registration semantics explicitly as well as
    // through the full-function template.
    static const uint8_t callbackRegistration[] = {0x48,0x89,0x43,0x60};
    static const uint8_t thisRegistration[] = {0x4c,0x89,0x73,0x58};
    // Only the four independently resolved LEA displacements are normalized.
    // The LEA opcodes, stores, and every other body byte remain exact.
    if (!Detail::matchesBytes(init, expectedInit, 0, 0x2f) ||
        !Detail::matchesBytes(init, expectedInit, 0x33, 0x3a) ||
        !Detail::matchesBytes(init, expectedInit, 0x3e, 0x45) ||
        !Detail::matchesBytes(init, expectedInit, 0x49, 0x50) ||
        !Detail::matchesBytes(init, expectedInit, 0x54, InitIfnetParamsSize) ||
        init[0x37] != 0x48 || init[0x38] != 0x8d || init[0x39] != 0x05 ||
        init[0x3e] != callbackRegistration[0] ||
        init[0x3f] != callbackRegistration[1] ||
        init[0x40] != callbackRegistration[2] ||
        init[0x41] != callbackRegistration[3] ||
        init[0x58] != thisRegistration[0] || init[0x59] != thisRegistration[1] ||
        init[0x5a] != thisRegistration[2] || init[0x5b] != thisRegistration[3])
        return false;

    uintptr_t outputLEATarget=0,callbackLEATarget=0,bpfLEATarget=0,
              detachLEATarget=0;
    // resolveRel32 accepts a complete instruction length; each LEA is 7 bytes.
    if (!Detail::resolveRel32(initAddress+InitOutputLEAOffset,7,init+0x2f,
                              outputLEATarget) ||
        !Detail::resolveRel32(initAddress+InitCallbackLEAOffset,7,init+0x3a,
                              callbackLEATarget) ||
        !Detail::resolveRel32(initAddress+InitBpfLEAOffset,7,init+0x45,
                              bpfLEATarget) ||
        !Detail::resolveRel32(initAddress+InitDetachLEAOffset,7,init+0x50,
                              detachLEATarget) ||
        outputLEATarget != targets.output ||
        callbackLEATarget != callbackAddress ||
        bpfLEATarget != targets.bpf || detachLEATarget != targets.detach)
        return false;

    if (!Detail::matchesBytes(callback, expectedCallback, 0, 0x18) ||
        !Detail::matchesBytes(callback, expectedCallback, 0x1c, 0x2e) ||
        !Detail::matchesBytes(callback, expectedCallback, 0x32, IfIoctlSize))
        return false;
    if (callback[0x17] != 0xe8 || callback[0x2d] != 0xe8) return false;
    uintptr_t softcTarget=0, inactiveTarget=0;
    if (!Detail::resolveRel32(callbackAddress+0x17, 5, callback+0x18,
                              softcTarget) ||
        !Detail::resolveRel32(callbackAddress+0x2d, 5, callback+0x2e,
                              inactiveTarget)) return false;
    return softcTarget == ifnetSoftcTarget &&
           inactiveTarget == isInactiveTarget;
}

} } // namespace PrivateMAC::NetworkCallbackContract

#endif
