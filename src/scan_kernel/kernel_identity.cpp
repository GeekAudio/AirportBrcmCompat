#include <Headers/kern_mach.hpp>
#include <mach-o/loader.h>
#include "kernel_identity.hpp"

namespace ScanKernelIdentity {
namespace {
constexpr uint8_t Kernel25G241UUID[16] = {
    0x12, 0x91, 0xd4, 0x4a, 0xc0, 0xcd, 0x3a, 0xc7,
    0xa9, 0xe4, 0xca, 0x27, 0x49, 0xb3, 0x39, 0x59
};
constexpr uint8_t Kernel25G332UUID[16] = {
    0x28, 0x26, 0x7f, 0xd5, 0x3e, 0x1e, 0x36, 0x86,
    0x8a, 0x1c, 0xe7, 0x3e, 0x24, 0x66, 0xfc, 0xfb
};
volatile uint32_t selectedProfile = static_cast<uint32_t>(Profile::Unsupported);

bool compiledProfile(Profile profile) {
#if defined(AIRPORT_BRCM_DUAL_PROFILE_25G241_25G332)
    return profile == Profile::Build25G241 || profile == Profile::Build25G332;
#elif defined(AIRPORT_BRCM_BASELINE_25G332)
    return profile == Profile::Build25G332;
#else
    return profile == Profile::Build25G241;
#endif
}

Profile profileForUUID(const uint8_t *uuid) {
    if (!uuid) return Profile::Unsupported;
    if (!memcmp(uuid, Kernel25G241UUID, sizeof(Kernel25G241UUID)))
        return compiledProfile(Profile::Build25G241) ? Profile::Build25G241 : Profile::Unsupported;
    if (!memcmp(uuid, Kernel25G332UUID, sizeof(Kernel25G332UUID)))
        return compiledProfile(Profile::Build25G332) ? Profile::Build25G332 : Profile::Unsupported;
    return Profile::Unsupported;
}

bool rememberProfile(Profile profile) {
    if (profile == Profile::Unsupported) return false;
    uint32_t expected = static_cast<uint32_t>(Profile::Unsupported);
    if (__atomic_compare_exchange_n(&selectedProfile, &expected, static_cast<uint32_t>(profile),
                                    false, __ATOMIC_RELEASE, __ATOMIC_ACQUIRE)) return true;
    return expected == static_cast<uint32_t>(profile);
}
// Checked against the actual release Lilu 1.7.3 object allocation and member
// offsets, not just a header declaration. Reaudit if that Lilu build changes.
static_assert(sizeof(MachInfo) == 192, "Pinned Lilu MachInfo ABI changed");
static_assert(MachInfo::HeaderSize == 8192, "Pinned Lilu header bound changed");

struct OwnedInfo {
    MachInfo *info;
    explicit OwnedInfo(MachInfo *value) : info(value) {}
    ~OwnedInfo() {
        if (info) {
            // getRunningAddresses can partially initialise on failure. KC
            // LINKEDIT is borrowed (sym_buf_ro=true), never freed by deinit.
            info->deinit();
            MachInfo::deleter(info);
        }
    }
    OwnedInfo(const OwnedInfo &) = delete;
    OwnedInfo &operator=(const OwnedInfo &) = delete;
};

Profile matchingImage(const uint8_t *bytes, size_t range) {
    const auto *header = reinterpret_cast<const mach_header_64 *>(bytes);
    if (header->magic != MH_MAGIC_64 || header->cputype != CPU_TYPE_X86_64 ||
        header->filetype != MH_EXECUTE ||
        header->sizeofcmds > range - sizeof(*header) ||
        header->ncmds > header->sizeofcmds / sizeof(load_command)) return Profile::Unsupported;

    size_t offset = sizeof(*header);
    const size_t end = offset + header->sizeofcmds;
    unsigned found = 0;
    Profile matched = Profile::Unsupported;
    for (uint32_t index = 0; index < header->ncmds; ++index) {
        if (offset > end || end - offset < sizeof(load_command)) return Profile::Unsupported;
        const auto *command = reinterpret_cast<const load_command *>(bytes + offset);
        if (command->cmdsize < sizeof(load_command) || command->cmdsize % 8 != 0 ||
            command->cmdsize > end - offset) return Profile::Unsupported;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(uuid_command) || ++found != 1)
                return Profile::Unsupported;
            matched = profileForUUID(reinterpret_cast<const uuid_command *>(command)->uuid);
            if (matched == Profile::Unsupported) return Profile::Unsupported;
        }
        offset += command->cmdsize;
    }
    return offset == end && found == 1 ? matched : Profile::Unsupported;
}
}

Profile currentProfile() {
    return static_cast<Profile>(__atomic_load_n(&selectedProfile, __ATOMIC_ACQUIRE));
}

int32_t identifyRunningKernelProfile(Profile *profile) {
    if (!profile) return 4;
    *profile = Profile::Unsupported;
    // Public Lilu API, independent object. No filesystem init, direct private
    // KPI import, mutation of the patcher's KernelID object, or fallback pin.
    OwnedInfo owned(MachInfo::create(true, "kernel"));
    if (!owned.info) return 3;
    if (owned.info->getRunningAddresses() != KERN_SUCCESS) return 4;
    uint8_t *header = nullptr;
    size_t size = 0;
    owned.info->getRunningPosition(header, size);
    if (!header || size < sizeof(mach_header_64) ||
        reinterpret_cast<uintptr_t>(header) % alignof(mach_header_64) != 0) return 4;
    // Lilu reports the image span, which may include gaps. The UUID parser is
    // restricted to its header window; it never walks that whole span.
    const size_t headerRange = size < MachInfo::HeaderSize ? size : MachInfo::HeaderSize;
    if (reinterpret_cast<uintptr_t>(header) > UINTPTR_MAX - headerRange) return 4;
    const Profile matched = matchingImage(header, headerRange);
    if (matched == Profile::Unsupported || !rememberProfile(matched)) return 5;
    *profile = matched;
    return 0;
}

int32_t verifyRunningKernelIdentity() {
    Profile profile = Profile::Unsupported;
    return identifyRunningKernelProfile(&profile);
}

int32_t verifyRunningKernelCodeRange(uintptr_t address,uint64_t needed) {
    if (!address || !needed || address>UINTPTR_MAX-needed) return 6;
    OwnedInfo owned(MachInfo::create(true,"kernel"));
    if (!owned.info) return 3;
    if (owned.info->getRunningAddresses()!=KERN_SUCCESS) return 4;
    uint8_t *bytes=nullptr;size_t span=0;owned.info->getRunningPosition(bytes,span);
    if (!bytes || span<sizeof(mach_header_64) ||
        reinterpret_cast<uintptr_t>(bytes)%alignof(mach_header_64)) return 4;
    const size_t range=span<MachInfo::HeaderSize?span:MachInfo::HeaderSize;
    if (reinterpret_cast<uintptr_t>(bytes)>UINTPTR_MAX-range) return 5;
    const Profile matched = matchingImage(bytes,range);
    if (matched == Profile::Unsupported || !rememberProfile(matched)) return 5;
    const auto *header=reinterpret_cast<const mach_header_64 *>(bytes);
    const size_t end=sizeof(*header)+header->sizeofcmds;
    uintptr_t slide=0;unsigned textFound=0;
    for (size_t offset=sizeof(*header);offset<end;) {
        const auto *cmd=reinterpret_cast<const load_command *>(bytes+offset);
        if (cmd->cmd==LC_SEGMENT_64) {
            if (cmd->cmdsize<sizeof(segment_command_64)) return 6;
            const auto *seg=reinterpret_cast<const segment_command_64 *>(cmd);
            static const char text[16]="__TEXT";
            if (!memcmp(seg->segname,text,16)) {
                if (++textFound!=1 || reinterpret_cast<uintptr_t>(bytes)<seg->vmaddr) return 6;
                slide=reinterpret_cast<uintptr_t>(bytes)-seg->vmaddr;
            }
        }
        offset+=cmd->cmdsize;
    }
    if (textFound!=1) return 6;
    for (size_t offset=sizeof(*header);offset<end;) {
        const auto *cmd=reinterpret_cast<const load_command *>(bytes+offset);
        if (cmd->cmd==LC_SEGMENT_64) {
            const auto *seg=reinterpret_cast<const segment_command_64 *>(cmd);
            if ((seg->initprot&4) && (seg->maxprot&4) && seg->vmaddr<=UINTPTR_MAX-slide) {
                const uintptr_t begin=seg->vmaddr+slide;
                if (seg->vmsize && seg->vmsize<=UINTPTR_MAX-begin &&
                    address>=begin && address-begin<=seg->vmsize &&
                    needed<=seg->vmsize-(address-begin)) return 0;
            }
        }
        offset+=cmd->cmdsize;
    }
    return 6;
}
}
