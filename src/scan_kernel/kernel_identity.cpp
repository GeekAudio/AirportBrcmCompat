#include <Headers/kern_mach.hpp>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <string.h>
#include "kernel_identity.hpp"

namespace ScanKernelIdentity {
namespace {
enum : uint32_t { UUIDEmpty=0, UUIDWriting=1, UUIDVerified=2, UUIDRejected=3 };
volatile uint32_t identityState=UUIDEmpty;
uint8_t cachedUUID[16] {};

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

bool nonzeroUUID(const uint8_t uuid[16]) {
    uint8_t bits=0;
    for (size_t i=0;i<16;++i) bits|=uuid[i];
    return bits!=0;
}

bool segmentShape(const segment_command_64 *segment,size_t commandSize) {
    if (commandSize<sizeof(*segment)) return false;
    const size_t available=commandSize-sizeof(*segment);
    if (segment->nsects>available/sizeof(section_64) ||
        available!=segment->nsects*sizeof(section_64) ||
        segment->vmaddr>UINT64_MAX-segment->vmsize ||
        segment->filesize>segment->vmsize ||
        segment->fileoff>UINT64_MAX-segment->filesize) return false;
    const auto *sections=reinterpret_cast<const section_64 *>(segment+1);
    for (uint32_t i=0;i<segment->nsects;++i) {
        const auto &section=sections[i];
        if (section.addr<segment->vmaddr || section.addr-segment->vmaddr>segment->vmsize ||
            section.size>segment->vmsize-(section.addr-segment->vmaddr)) return false;
    }
    return true;
}

// Structural identity only: bounded x86_64 kernel Mach-O with one nonzero
// LC_UUID. The UUID is cached to detect an identity change during this boot;
// it does not imply support for any kernel, OS build, or private ABI.
bool parseKernelHeader(const uint8_t *bytes,size_t range,uint8_t uuid[16]) {
    if (!bytes || !uuid || range<sizeof(mach_header_64)) return false;
    const auto *header=reinterpret_cast<const mach_header_64 *>(bytes);
    if (header->magic!=MH_MAGIC_64 || header->cputype!=CPU_TYPE_X86_64 ||
        header->filetype!=MH_EXECUTE || header->sizeofcmds>range-sizeof(*header) ||
        !header->ncmds || header->ncmds>header->sizeofcmds/sizeof(load_command)) return false;

    const size_t end=sizeof(*header)+header->sizeofcmds;
    size_t offset=sizeof(*header);
    unsigned uuidCount=0;
    uint8_t foundUUID[16] {};
    for (uint32_t i=0;i<header->ncmds;++i) {
        if (offset>end || end-offset<sizeof(load_command)) return false;
        const auto *command=reinterpret_cast<const load_command *>(bytes+offset);
        if (command->cmdsize<sizeof(*command) || command->cmdsize%8 ||
            command->cmdsize>end-offset) return false;
        if (command->cmd==LC_UUID) {
            if (command->cmdsize!=sizeof(uuid_command) || ++uuidCount!=1) return false;
            memcpy(foundUUID,reinterpret_cast<const uuid_command *>(command)->uuid,sizeof(foundUUID));
        } else if (command->cmd==LC_SEGMENT_64) {
            if (!segmentShape(reinterpret_cast<const segment_command_64 *>(command),command->cmdsize))
                return false;
        }
        offset+=command->cmdsize;
    }
    if (offset!=end || uuidCount!=1 || !nonzeroUUID(foundUUID)) return false;
    memcpy(uuid,foundUUID,sizeof(foundUUID));
    return true;
}

bool rememberUUID(const uint8_t uuid[16]) {
    uint32_t state=__atomic_load_n(&identityState,__ATOMIC_ACQUIRE);
    if (state==UUIDEmpty) {
        uint32_t expected=UUIDEmpty;
        if (__atomic_compare_exchange_n(&identityState,&expected,UUIDWriting,false,
                                        __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) {
            memcpy(cachedUUID,uuid,sizeof(cachedUUID));
            __atomic_store_n(&identityState,UUIDVerified,__ATOMIC_RELEASE);
            return true;
        }
        state=expected;
    }
    if (state==UUIDWriting || state==UUIDRejected) return false;
    if (state!=UUIDVerified) return false;
    if (!memcmp(cachedUUID,uuid,sizeof(cachedUUID))) return true;
    uint32_t expected=UUIDVerified;
    __atomic_compare_exchange_n(&identityState,&expected,UUIDRejected,false,
                                __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    return false;
}

void rejectCachedIdentity() {
    uint32_t expected=UUIDVerified;
    __atomic_compare_exchange_n(&identityState,&expected,UUIDRejected,false,
                                __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
}

int32_t runningKernelUUID(uint8_t uuid[16]) {
    OwnedInfo owned(MachInfo::create(true,"kernel"));
    if (!owned.info) return 3;
    if (owned.info->getRunningAddresses()!=KERN_SUCCESS) return 4;
    uint8_t *header=nullptr;
    size_t size=0;
    owned.info->getRunningPosition(header,size);
    if (!header || size<sizeof(mach_header_64) ||
        reinterpret_cast<uintptr_t>(header)%alignof(mach_header_64)!=0) return 4;
    const size_t headerRange=size<MachInfo::HeaderSize?size:MachInfo::HeaderSize;
    if (reinterpret_cast<uintptr_t>(header)>UINTPTR_MAX-headerRange) return 4;
    return parseKernelHeader(header,headerRange,uuid)?0:5;
}
}

Profile currentProfile() {
    switch (__atomic_load_n(&identityState,__ATOMIC_ACQUIRE)) {
        case UUIDVerified:return Profile::Structural;
        case UUIDRejected:return Profile::Unsupported;
        default:return Profile::Pending;
    }
}

int32_t identifyRunningKernelProfile(Profile *profile) {
    if (!profile) return 4;
    *profile=Profile::Pending;
    uint8_t uuid[16] {};
    const int32_t status=runningKernelUUID(uuid);
    if (status) {
        if (status==5) rejectCachedIdentity();
        *profile=Profile::Unsupported;
        return status;
    }
    if (!rememberUUID(uuid)) {
        *profile=Profile::Unsupported;
        return 5;
    }
    *profile=Profile::Structural;
    return 0;
}

bool copyRunningKernelUUID(uint8_t uuid[16]) {
    if (!uuid) return false;
    memset(uuid,0,16);
    if (__atomic_load_n(&identityState,__ATOMIC_ACQUIRE)!=UUIDVerified) return false;
    memcpy(uuid,cachedUUID,16);
    if (__atomic_load_n(&identityState,__ATOMIC_ACQUIRE)==UUIDVerified) return true;
    memset(uuid,0,16);
    return false;
}

int32_t verifyRunningKernelIdentity() {
    Profile state=Profile::Pending;
    return identifyRunningKernelProfile(&state);
}

namespace {
int32_t verifyRunningKernelRange(uintptr_t address,uint64_t needed,uint32_t requiredProtection) {
    if (!address || !needed || address>UINTPTR_MAX-needed) return 6;
    OwnedInfo owned(MachInfo::create(true,"kernel"));
    if (!owned.info) return 3;
    if (owned.info->getRunningAddresses()!=KERN_SUCCESS) return 4;
    uint8_t *bytes=nullptr;
    size_t span=0;
    owned.info->getRunningPosition(bytes,span);
    if (!bytes || span<sizeof(mach_header_64) ||
        reinterpret_cast<uintptr_t>(bytes)%alignof(mach_header_64)!=0) return 4;
    const uintptr_t imageBase=reinterpret_cast<uintptr_t>(bytes);
    if (imageBase>UINTPTR_MAX-span) return 5;
    const size_t headerRange=span<MachInfo::HeaderSize?span:MachInfo::HeaderSize;
    uint8_t uuid[16] {};
    if (!parseKernelHeader(bytes,headerRange,uuid)) {
        rejectCachedIdentity();return 5;
    }
    if (!rememberUUID(uuid)) return 5;

    const auto *header=reinterpret_cast<const mach_header_64 *>(bytes);
    const size_t end=sizeof(*header)+header->sizeofcmds;
    uintptr_t slide=0;
    unsigned textCount=0;
    for (size_t offset=sizeof(*header);offset<end;) {
        const auto *command=reinterpret_cast<const load_command *>(bytes+offset);
        if (command->cmd==LC_SEGMENT_64) {
            const auto *segment=reinterpret_cast<const segment_command_64 *>(command);
            static const char textName[16]="__TEXT";
            if (!memcmp(segment->segname,textName,sizeof(textName))) {
                if (++textCount!=1 || !segment->vmsize ||
                    !(segment->initprot&VM_PROT_EXECUTE) ||
                    !(segment->maxprot&VM_PROT_EXECUTE) ||
                    reinterpret_cast<uintptr_t>(bytes)<segment->vmaddr) return 6;
                slide=reinterpret_cast<uintptr_t>(bytes)-segment->vmaddr;
            }
        }
        offset+=command->cmdsize;
    }
    if (textCount!=1) return 6;

    if (address<imageBase || address-imageBase>span ||
        needed>span-(address-imageBase)) return 6;

    for (size_t offset=sizeof(*header);offset<end;) {
        const auto *command=reinterpret_cast<const load_command *>(bytes+offset);
        if (command->cmd==LC_SEGMENT_64) {
            const auto *segment=reinterpret_cast<const segment_command_64 *>(command);
            if ((segment->initprot&requiredProtection)==requiredProtection &&
                (segment->maxprot&requiredProtection)==requiredProtection &&
                segment->vmsize && segment->vmaddr<=UINTPTR_MAX-slide) {
                const uintptr_t begin=static_cast<uintptr_t>(segment->vmaddr)+slide;
                if (segment->vmsize<=UINTPTR_MAX-begin && address>=begin &&
                    address-begin<=segment->vmsize &&
                    needed<=segment->vmsize-(address-begin)) {
                    return 0;
                }
            }
        }
        offset+=command->cmdsize;
    }
    return 6;
}
}

int32_t verifyRunningKernelCodeRange(uintptr_t address,uint64_t needed) {
    return verifyRunningKernelRange(address,needed,VM_PROT_EXECUTE);
}

int32_t verifyRunningKernelReadableRange(uintptr_t address,uint64_t needed) {
    return verifyRunningKernelRange(address,needed,VM_PROT_READ);
}
}
