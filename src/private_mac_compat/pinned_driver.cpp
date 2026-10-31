#include "pinned_driver.hpp"
#include <mach-o/loader.h>

namespace PrivateMAC {
namespace {
static_assert(sizeof(uintptr_t) == 8, "Pinned x86_64 driver ABI required");

constexpr uint8_t ExpectedUUID[16] = {
    0xe4, 0x67, 0x8f, 0xeb, 0x1d, 0xc1, 0x35, 0xcc,
    0x93, 0x06, 0x48, 0x02, 0x10, 0x83, 0xd0, 0x4a
};
constexpr size_t HeaderBound = 8192;
constexpr size_t TextStart = 0x990, TextEnd = 0x349aa0;

// All spans are offsets from this image's __TEXT/header base, with exclusive
// ends at the next symbol. They are not offsets into an outer KC/fileset.
constexpr size_t SetHardwareOffset = 0x38b96, SetHardwareEnd = 0x38c60;
constexpr size_t GetHardwareOffset = 0x38b7a, GetHardwareEnd = 0x38b96;
constexpr size_t IovarOffset = 0x3824a, IovarEnd = 0x3830e;
constexpr size_t StateOffset = 0x3b9ce, StateEnd = 0x3ba2a;
constexpr size_t FindBssOffset = 0x2e314, FindBssEnd = 0x2e326;
constexpr size_t AssocProgressOffset = 0x110309, AssocProgressEnd = 0x11031a;
constexpr size_t AssociateOffset = 0x42b8e, AssociateEnd = 0x438f8;
constexpr size_t AuthOffset = 0x438f8, AuthEnd = 0x43b42;
constexpr size_t FindTargetOffset = 0x178d0a, FindTargetEnd = 0x178dbd;
constexpr size_t AuthCallOffset = 0x4322c, AuthReturnOffset = 0x43231;
constexpr size_t AssociateCallOffset = 0x59a65, AssociateReturnOffset = 0x59a6a;
constexpr size_t FindJumpOffset = 0x2e320;

// Complete instructions only. In particular SetHardware stops at +13 BEFORE
// the external GOT RIP-load at 0x38ba3. No external symbol/GOT displacement or
// external call relocation is compared. Internal rel32 branches are invariant
// under a single-image slide and their decoded targets are checked separately.
constexpr uint8_t SetHardwareGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x53,0x48,0x83,0xec,0x18};
constexpr uint8_t GetHardwareGuard[] = {0x55,0x48,0x89,0xe5,0x48,0x8b,0x87,0x18,0x0a,0x00,0x00,0x8b,0x48,0x08,0x0f,0xb7,0x40,0x0c,0x66,0x89,0x46,0x04,0x89,0x0e,0x31,0xc0,0x5d,0xc3};
constexpr uint8_t IovarGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x18,0x4c,0x89,0x4d,0xc8,0x4d,0x89,0xc4,0x49,0x89,0xcd,0x49,0x89,0xd7,0x48,0x89,0x75,0xd0,0x49,0x89,0xfe,0x8a,0x5d,0x10,0x48,0x8b,0x75,0x18};
constexpr uint8_t StateGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x85,0xd2,0x74,0x2e,0x49,0x89,0xd6,0x48,0x89,0xf3,0x48,0xc7,0x02,0x01,0x00,0x00,0x00};
constexpr uint8_t FindBssGuard[] = {0x55,0x48,0x89,0xe5,0x48,0x8b,0xbf,0x10,0x0a,0x00,0x00,0x5d,0xe9,0xe5,0xa9,0x14,0x00};
constexpr uint8_t AssocProgressGuard[] = {0x55,0x48,0x89,0xe5,0x48,0x83,0xbf,0xe8,0x05,0x00,0x00,0x00,0x0f,0x95,0xc0,0x5d,0xc3};
constexpr uint8_t AssociateGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec,0x28,0x02,0x00,0x00,0x49,0x89,0xd5,0x49,0x89,0xf7,0x49,0x89,0xfe};
constexpr uint8_t AuthGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x28,0x49,0x89,0xd5,0x49,0x89,0xf7,0x49,0x89,0xfe};
constexpr uint8_t AuthCallerGuard[] = {0x41,0x0f,0xb7,0x45,0x06,0x48,0x8d,0x95,0xe0,0xfd,0xff,0xff,0x89,0x42,0x04,0x41,0x0f,0xb7,0x45,0x08,0x89,0x42,0x08,0x48,0x89,0xdf,0x4c,0x89,0xfe,0xe8,0xc7,0x06,0x00,0x00};
constexpr uint8_t AssociateCallerGuard[] = {0x4c,0x89,0xff,0x4c,0x89,0xe6,0x48,0x8b,0x55,0xb8,0xe8,0x24,0x91,0xfe,0xff};
constexpr uint8_t FindTargetGuard[] = {0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50,0x49,0x89,0xfe,0x48,0x85,0xf6,0x74,0x14};
constexpr uint8_t MainBranchGuard[] = {0x4d,0x8b,0xbe,0x40,0x03,0x00,0x00,0xeb,0x6e};

bool same(const uint8_t *bytes, const uint8_t *expected, size_t n) {
    for (size_t i=0; i<n; ++i) if (bytes[i] != expected[i]) return false;
    return true;
}
bool name(const char actual[16], const char *expected) {
    for (size_t i=0; i<16; ++i) {
        if (actual[i] != expected[i]) return false;
        if (!expected[i]) {
            for (++i; i<16; ++i) if (actual[i]) return false;
            return true;
        }
    }
    return false;
}
bool bounded(size_t offset, size_t n, size_t limit) {
    return offset <= limit && n <= limit-offset;
}
bool textSpan(size_t begin, size_t end, size_t imageSize) {
    return begin >= TextStart && end > begin && end <= TextEnd && end <= imageSize;
}

DriverPinStatus image(const uint8_t *bytes, size_t size) {
    const auto *h = reinterpret_cast<const mach_header_64 *>(bytes);
    if (h->magic != MH_MAGIC_64 || h->cputype != CPU_TYPE_X86_64 ||
        h->cpusubtype != CPU_SUBTYPE_X86_64_ALL || h->filetype != MH_KEXT_BUNDLE ||
        h->sizeofcmds > HeaderBound-sizeof(*h) ||
        h->sizeofcmds > size-sizeof(*h) || !h->ncmds ||
        h->ncmds > h->sizeofcmds/sizeof(load_command)) return DriverPinStatus::MachO;
    size_t offset=sizeof(*h), end=offset+h->sizeofcmds;
    unsigned uuidCount=0, textCount=0, codeCount=0;
    bool uuidMatches=false, textMatches=false;
    for (uint32_t i=0; i<h->ncmds; ++i) {
        if (!bounded(offset,sizeof(load_command),end)) return DriverPinStatus::MachO;
        const auto *c=reinterpret_cast<const load_command *>(bytes+offset);
        if (c->cmdsize < sizeof(*c) || c->cmdsize%8 ||
            !bounded(offset,c->cmdsize,end)) return DriverPinStatus::MachO;
        if (c->cmd == LC_UUID) {
            if (c->cmdsize != sizeof(uuid_command) || ++uuidCount != 1)
                return DriverPinStatus::UUID;
            uuidMatches=same(reinterpret_cast<const uuid_command *>(c)->uuid,
                             ExpectedUUID,sizeof(ExpectedUUID));
        } else if (c->cmd == LC_SEGMENT_64) {
            if (c->cmdsize < sizeof(segment_command_64)) return DriverPinStatus::MachO;
            const auto *s=reinterpret_cast<const segment_command_64 *>(c);
            const size_t available=c->cmdsize-sizeof(*s);
            if (s->nsects > available/sizeof(section_64) ||
                available != s->nsects*sizeof(section_64)) return DriverPinStatus::MachO;
            if (name(s->segname,"__TEXT")) {
                if (++textCount != 1) return DriverPinStatus::Text;
                if (!(s->initprot&4) || !(s->maxprot&4) || s->vmsize < TextEnd ||
                    s->vmsize > size || s->vmaddr > UINT64_MAX-s->vmsize)
                    return DriverPinStatus::Text;
                const auto *sections=reinterpret_cast<const section_64 *>(s+1);
                for (uint32_t j=0; j<s->nsects; ++j) {
                    const auto &sec=sections[j];
                    if (name(sec.sectname,"__text")) {
                        if (++codeCount != 1 || !name(sec.segname,"__TEXT") ||
                            sec.addr < s->vmaddr || sec.addr-s->vmaddr != TextStart ||
                            sec.size != TextEnd-TextStart ||
                            sec.size > s->vmsize-TextStart ||
                            !(sec.flags&S_ATTR_PURE_INSTRUCTIONS)) return DriverPinStatus::Text;
                        textMatches=true;
                    }
                }
            }
        }
        offset+=c->cmdsize;
    }
    if (offset != end) return DriverPinStatus::MachO;
    if (uuidCount != 1 || !uuidMatches) return DriverPinStatus::UUID;
    return textCount == 1 && codeCount == 1 && textMatches ?
        DriverPinStatus::Passed : DriverPinStatus::Text;
}

// Decode only an already bounded E8/E9 instruction, using image-relative math
// so neither a slide nor signed negative rel32 can overflow a kernel address.
bool relativeTarget(const uint8_t *bytes, size_t size, size_t call,
                    uint8_t opcode, size_t target, size_t returnOffset) {
    if (!bounded(call,5,size) || bytes[call] != opcode || returnOffset != call+5)
        return false;
    uint32_t raw=0;
    for (size_t i=0; i<4; ++i) raw |= uint32_t(bytes[call+1+i]) << (8*i);
    const int64_t displacement = raw <= INT32_MAX ? int64_t(raw) :
        int64_t(raw)-INT64_C(0x100000000);
    return int64_t(returnOffset)+displacement == int64_t(target);
}
}

DriverPinStatus initializeDriverPins(const void *imageBase, size_t imageSize,
                                     DriverPins &out) {
    out=DriverPins {};
    const uintptr_t base=reinterpret_cast<uintptr_t>(imageBase);
    if (!base || base%alignof(mach_header_64) || imageSize<sizeof(mach_header_64) ||
        imageSize > SIZE_MAX/2 || base > UINTPTR_MAX-imageSize)
        return DriverPinStatus::Input;
    const auto *bytes=static_cast<const uint8_t *>(imageBase);
    auto status=image(bytes,imageSize);
    if (status != DriverPinStatus::Passed) return status;
    const size_t spans[][2] = {
        {SetHardwareOffset,SetHardwareEnd},{GetHardwareOffset,GetHardwareEnd},
        {IovarOffset,IovarEnd},{StateOffset,StateEnd},{FindBssOffset,FindBssEnd},
        {AssocProgressOffset,AssocProgressEnd},{AssociateOffset,AssociateEnd},
        {AuthOffset,AuthEnd},{FindTargetOffset,FindTargetEnd},
        {0x4320f,AuthReturnOffset},{0x59a5b,AssociateReturnOffset}
    };
    for (const auto &span:spans)
        if (!textSpan(span[0],span[1],imageSize)) return DriverPinStatus::Range;
    struct Check {size_t offset; const uint8_t *expected; size_t length; DriverPinStatus error;};
#define PIN_CHECK(offset, guard, error) {offset,guard,sizeof(guard),DriverPinStatus::error}
    const Check checks[] = {
        PIN_CHECK(SetHardwareOffset,SetHardwareGuard,SetHardwareGuard),
        PIN_CHECK(GetHardwareOffset,GetHardwareGuard,GetHardwareGuard),
        PIN_CHECK(IovarOffset,IovarGuard,IovarGuard),
        PIN_CHECK(StateOffset,StateGuard,StateGuard),
        PIN_CHECK(FindBssOffset,FindBssGuard,FindBssGuard),
        PIN_CHECK(AssocProgressOffset,AssocProgressGuard,AssocProgressGuard),
        PIN_CHECK(AssociateOffset,AssociateGuard,AssociateGuard),
        PIN_CHECK(AuthOffset,AuthGuard,AuthGuard),
        PIN_CHECK(0x4320f,AuthCallerGuard,AuthCallerGuard),
        PIN_CHECK(0x59a5b,AssociateCallerGuard,AssociateCallerGuard),
        PIN_CHECK(FindTargetOffset,FindTargetGuard,FindTargetGuard),
        PIN_CHECK(0x178d34,MainBranchGuard,MainBranchGuard)
    };
#undef PIN_CHECK
    for (const auto &check:checks) {
        if (!bounded(check.offset,check.length,imageSize)) return DriverPinStatus::Range;
        if (!same(bytes+check.offset,check.expected,check.length)) return check.error;
    }
    if (!relativeTarget(bytes,imageSize,AuthCallOffset,0xe8,AuthOffset,AuthReturnOffset))
        return DriverPinStatus::AuthCall;
    if (!relativeTarget(bytes,imageSize,AssociateCallOffset,0xe8,AssociateOffset,
                        AssociateReturnOffset)) return DriverPinStatus::AssociateCall;
    if (!relativeTarget(bytes,imageSize,FindJumpOffset,0xe9,FindTargetOffset,FindJumpOffset+5))
        return DriverPinStatus::FindJump;

    DriverPins candidate;
    candidate.setHardwareAddress=reinterpret_cast<DriverPins::SetHardwareAddress>(base+SetHardwareOffset);
    candidate.getHardwareAddress=reinterpret_cast<DriverPins::GetHardwareAddress>(base+GetHardwareOffset);
    candidate.iovar=reinterpret_cast<DriverPins::Iovar>(base+IovarOffset);
    candidate.getState=reinterpret_cast<DriverPins::GetState>(base+StateOffset);
    candidate.findBssCfg=reinterpret_cast<DriverPins::FindBssCfg>(base+FindBssOffset);
    candidate.assocInProgress=reinterpret_cast<DriverPins::AssocInProgress>(base+AssocProgressOffset);
    candidate.setAssociate=reinterpret_cast<DriverPins::SetAssociate>(base+AssociateOffset);
    candidate.setAuthType=reinterpret_cast<DriverPins::SetAuthType>(base+AuthOffset);
    candidate.authCallerReturn=base+AuthReturnOffset;
    candidate.associateCallerReturn=base+AssociateReturnOffset;
    out=candidate;
    return DriverPinStatus::Passed;
}
}
