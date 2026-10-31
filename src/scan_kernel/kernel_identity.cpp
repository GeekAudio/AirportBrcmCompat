#include <Headers/kern_patcher.hpp>
#include <IOKit/IOLib.h>
#include <mach/vm_types.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#include <string.h>
#include "kernel_identity.hpp"

namespace ScanKernelIdentity {
namespace {
enum : uint32_t { UUIDEmpty=0, UUIDWriting=1, UUIDVerified=2, UUIDRejected=3 };
volatile uint32_t identityState=UUIDEmpty;
uint8_t cachedUUID[16] {};

// This private XNU reader has the same signature in Darwin 23/24/25. Resolve
// it at runtime; absence or inconsistent symbol addresses disables admission.
// No framework-private C++ object is allocated or read. Both ranges are wired:
// the kernel image and IOMalloc storage (or this thread's kernel stack).
using ReadWiredMemory = vm_size_t (*)(vm_offset_t, vm_offset_t, vm_size_t);
constexpr size_t MaxHeaderBytes=64U*1024U;
constexpr uint64_t MaxProbeBytes=1024U*1024U;
volatile uint32_t sourceState=0; // 0: unconfigured; 1: configuring; 2: ready; 3: failed
uintptr_t kernelHeader=0;
ReadWiredMemory readWiredMemory=nullptr;

struct OwnedHeader {
    uint8_t *bytes=nullptr;
    size_t size=0;
    ~OwnedHeader() { if (bytes) IOFree(bytes,size); }
    OwnedHeader() = default;
    OwnedHeader(const OwnedHeader &) = delete;
    OwnedHeader &operator=(const OwnedHeader &) = delete;
};

bool readExact(uintptr_t source,void *destination,size_t size) {
    if (__atomic_load_n(&sourceState,__ATOMIC_ACQUIRE)!=2 || !source ||
        !destination || !size || source>UINTPTR_MAX-size) return false;
    return readWiredMemory(static_cast<vm_offset_t>(source),
        reinterpret_cast<vm_offset_t>(destination),static_cast<vm_size_t>(size))==size;
}

int32_t copyHeader(OwnedHeader &owned) {
    if (__atomic_load_n(&sourceState,__ATOMIC_ACQUIRE)!=2) return 4;
    mach_header_64 first {};
    if (!readExact(kernelHeader,&first,sizeof(first))) return 4;
    if (first.magic!=MH_MAGIC_64 || first.cputype!=CPU_TYPE_X86_64 ||
        first.filetype!=MH_EXECUTE || !first.ncmds ||
        first.sizeofcmds>MaxHeaderBytes-sizeof(first) ||
        first.ncmds>first.sizeofcmds/sizeof(load_command)) return 5;
    owned.size=sizeof(first)+first.sizeofcmds;
    owned.bytes=static_cast<uint8_t *>(IOMalloc(owned.size));
    if (!owned.bytes) return 3;
    if (!readExact(kernelHeader,owned.bytes,owned.size)) return 4;
    // Do not parse a length from one observation with bytes from another.
    if (memcmp(owned.bytes,&first,sizeof(first))) return 5;
    return 0;
}

// Header/segment declarations alone do not prove that a range is mapped.
// Probe using the same no-fault reader, in bounded stack chunks. Kernel text
// and data remain wired for the lifetime of this non-unloadable plugin.
bool mappedRange(uintptr_t address,uint64_t size) {
    if (size>MaxProbeBytes) return false;
    uint8_t probe[128];
    while (size) {
        const size_t count=size<sizeof(probe)?static_cast<size_t>(size):sizeof(probe);
        if (!readExact(address,probe,count)) return false;
        address+=count;size-=count;
    }
    return true;
}

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
        (segment->vmsize && segment->filesize>segment->vmsize) ||
        segment->fileoff>UINT64_MAX-segment->filesize) return false;
    const auto *sections=reinterpret_cast<const section_64 *>(segment+1);
    for (uint32_t i=0;i<segment->nsects;++i) {
        const auto &section=sections[i];
        // Standalone kernels can retain file-only debug/type data (e.g. CTF)
        // with vmsize == 0. Check its file extent, without treating the bytes
        // as a mapped segment. Kernel collections may strip this section to
        // size/offset zero. Range admission below excludes all zero-VM spans.
        if (!segment->vmsize) {
            if (!section.size) continue;
            if (section.addr>UINT64_MAX-section.size ||
                section.offset<segment->fileoff ||
                section.offset-segment->fileoff>segment->filesize ||
                section.size>segment->filesize-(section.offset-segment->fileoff)) return false;
            continue;
        }
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
    OwnedHeader owned;
    const int32_t status=copyHeader(owned);
    if (status) return status;
    return parseKernelHeader(owned.bytes,owned.size,uuid)?0:5;
}
}

int32_t initialize(KernelPatcher &patcher) {
    uint32_t expected=0;
    if (!__atomic_compare_exchange_n(&sourceState,&expected,1,false,
                                    __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
        return expected==2?0:4;
    // The kernel collection can relocate the inner kernel relative to the
    // standalone file, even with the same UUID. Before invoking ANY resolved
    // helper, compare two symbol addresses to actual loader-resolved public
    // imports. Reject a stale disk/slide view; do not guess a correction.
    patcher.clearError();
    const auto log=patcher.solveSymbol(KernelPatcher::KernelID,"_IOLog");
    const bool logOK=log==reinterpret_cast<uintptr_t>(&IOLog) &&
        patcher.getError()==KernelPatcher::Error::NoError;
    patcher.clearError();
    const auto sleep=patcher.solveSymbol(KernelPatcher::KernelID,"_IOSleep");
    const bool sleepOK=sleep==reinterpret_cast<uintptr_t>(&IOSleep) &&
        patcher.getError()==KernelPatcher::Error::NoError;
    patcher.clearError();
    if (!logOK || !sleepOK) {
        __atomic_store_n(&sourceState,3,__ATOMIC_RELEASE);
        return 4;
    }
    const uintptr_t header=patcher.solveSymbol(KernelPatcher::KernelID,"__mh_execute_header");
    const bool headerOK=header && patcher.getError()==KernelPatcher::Error::NoError;
    patcher.clearError();
    const uintptr_t reader=patcher.solveSymbol(KernelPatcher::KernelID,"_ml_nofault_copy");
    const bool readerOK=reader && patcher.getError()==KernelPatcher::Error::NoError;
    patcher.clearError();
    if (!headerOK || !readerOK || header%alignof(mach_header_64) ||
        header>UINTPTR_MAX-MaxHeaderBytes) {
        __atomic_store_n(&sourceState,3,__ATOMIC_RELEASE);
        return 4;
    }
    kernelHeader=header;
    readWiredMemory=reinterpret_cast<ReadWiredMemory>(reader);
    __atomic_store_n(&sourceState,2,__ATOMIC_RELEASE);
    return 0;
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
    OwnedHeader owned;
    const int32_t status=copyHeader(owned);
    if (status) {
        if (status==5) rejectCachedIdentity();
        return status;
    }
    const uint8_t *bytes=owned.bytes;
    const size_t headerRange=owned.size;
    const uintptr_t imageBase=kernelHeader;
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
                    imageBase<segment->vmaddr) return 6;
                slide=imageBase-segment->vmaddr;
            }
        }
        offset+=command->cmdsize;
    }
    if (textCount!=1) return 6;

    if (address<imageBase) return 6;

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
                    return mappedRange(address,needed)?0:6;
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
