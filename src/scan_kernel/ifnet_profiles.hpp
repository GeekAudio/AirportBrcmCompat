#ifndef AIRPORT_BRCM_IFNET_PROFILES_HPP
#define AIRPORT_BRCM_IFNET_PROFILES_HPP
#include "kernel_contracts.hpp"

namespace KernelContracts {
// Additional independently inspected ifnet_ioctl implementations. Admission
// uses code and resolved symbols, never a kernel version or UUID. Anonymous
// references retain their displacements in the digest; they are not wildcarded.
// Provenance: official Sonoma, Sequoia and Tahoe BootKC samples recorded in
// validation/compatibility-contracts.json. These descriptors do not establish
// whole-system Wi-Fi support.
namespace IfnetProfiles {
static const uint8_t MutexInlineDigest[32] = {0xa2,0x6e,0x82,0xbc,0x76,0xc3,0x17,0x1e,0xa0,0x70,0x95,0x43,0x25,0x36,0x1f,0xe9,0x46,0x2c,0x93,0xdf,0xcf,0x08,0xd3,0x94,0x6b,0x66,0x7d,0x9e,0x3f,0x48,0x77,0x77};
static const RelocationSpec MutexInlineRelocations[] = {
    {0x3d,0x3e,0x42,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x57,0x58,0x5c,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x67,0x68,0x6c,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0xdd,0xde,0xe2,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x104,0x105,0x109,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x160,0x161,0x165,RelocationKind::RelativeCall,"_thread_wakeup_prim",nullptr,0},
    {0x169,0x16a,0x16e,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x176,0x177,0x17b,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x1d9,0x1da,0x1de,RelocationKind::RelativeCall,"_thread_wakeup_prim",nullptr,0},
    {0x1e2,0x1e3,0x1e7,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x1ef,0x1f0,0x1f4,RelocationKind::RelativeCall,"_IORWLockRead","_lck_rw_lock_shared",0},
    {0x251,0x252,0x256,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x2ba,0x2bb,0x2bf,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
};
static const RelocationSpec MutexInlineMapped[] = {
    {0x193,0x196,0x19a,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x19a,0x19d,0x1a1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x1a6,0x1a7,0x1ab,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x29b,0x29c,0x2a0,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e7,0x2e8,0x2ec,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x325,0x328,0x32c,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x32c,0x32f,0x333,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x338,0x339,0x33d,RelocationKind::RelativeCall,nullptr,nullptr,0},
};
static const uint8_t MutexInlineAcquire[] = {0x8b,0x43,0x78,0x83,0xe0,0x07,0x83,0xf8,0x02,0x0f,0x85,0x22,0x01,0x00,0x00,0xff,0x43,0x7c,0x4c,0x89,0xf7};
static const uint8_t MutexInlineCallback[] = {0x48,0x8b,0x8b,0xf8,0x01,0x00,0x00,0x44,0x89,0xe0,0x48,0x85,0xc9,0x74,0x0d,0x48,0x89,0xdf,0x48,0x8b,0x75,0xd0,0x48,0x8b,0x55,0xc0,0xff,0xd1};
static const uint8_t MutexInlineRelease[] = {0x48,0x89,0xdf,0xe8,0xc0,0x04,0x00,0x00};

static const uint8_t MutexMonitorDigest[32] = {0xd1,0x28,0x1a,0x3e,0xcf,0xfb,0x35,0x66,0xa0,0xf7,0x72,0xd2,0xb4,0xee,0xa9,0xa4,0x98,0x10,0x56,0xa7,0x98,0xcb,0xf2,0x89,0x7f,0x3d,0xca,0x3a,0x4a,0xa1,0xd1,0x6a};
static const RelocationSpec MutexMonitorRelocations[] = {
    {0x3f,0x40,0x44,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x59,0x5a,0x5e,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x68,0x69,0x6d,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0xc9,0xca,0xce,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0xeb,0xec,0xf0,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x128,0x129,0x12d,RelocationKind::RelativeCall,"_if_flt_monitor_unbusy",nullptr,0},
    {0x130,0x131,0x135,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x140,0x141,0x145,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x159,0x15a,0x15e,RelocationKind::RelativeCall,"_if_flt_monitor_unbusy",nullptr,0},
    {0x161,0x162,0x166,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x16e,0x16f,0x173,RelocationKind::RelativeCall,"_IORWLockRead","_lck_rw_lock_shared",0},
    {0x1d2,0x1d3,0x1d7,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x240,0x241,0x245,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x26c,0x26d,0x271,RelocationKind::RelativeCall,"_if_proto_free",nullptr,0},
};
static const RelocationSpec MutexMonitorMapped[] = {
    {0x21d,0x21e,0x222,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2aa,0x2ad,0x2b1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2b1,0x2b4,0x2b8,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2bd,0x2be,0x2c2,RelocationKind::RelativeCall,nullptr,nullptr,0},
};
static const uint8_t MutexMonitorAcquire[] = {0x8b,0x43,0x78,0x83,0xe0,0x07,0x83,0xf8,0x02,0x0f,0x85,0xea,0x00,0x00,0x00,0xff,0x43,0x7c,0x4c,0x89,0xf7};
static const uint8_t MutexMonitorCallback[] = {0x48,0x8b,0x7d,0xd0,0x48,0x8b,0x87,0x60,0x02,0x00,0x00,0x48,0x85,0xc0,0x74,0x0d,0x48,0x8b,0x75,0xc8,0x48,0x8b,0x55,0xc0,0xff,0xd0};
static const uint8_t MutexMonitorRelease[] = {0x48,0x8b,0x7d,0xd0,0xe8,0xae,0x00,0x00,0x00};

// Atomic interface references with the original 0x260 driver callback field
// and a direct wakeup tail. The later implementation uses a different field
// and tail; matching the callback return offset alone cannot admit it.
static const uint8_t AtomicReferenceDigest[32] = {0x77,0x0b,0x4a,0x31,0x4b,0x78,0x77,0x1d,0xf7,0x77,0x48,0xd5,0x8b,0x12,0xc6,0x68,0x93,0x5d,0x74,0xf8,0x00,0x24,0x73,0x5a,0xc6,0x6d,0x32,0x65,0x42,0x68,0xd4,0x10};
// Independently inspected link layouts of the same instruction contract.
// Anonymous target displacements remain hashed; none are wildcarded.
static const uint8_t AtomicReferenceAdditionalDigests[][32] = {
    {0x0b,0x4c,0x66,0xd0,0x2b,0xec,0x56,0x28,0x52,0xe7,0x23,0xd0,0xa1,0xb5,0x09,0xa9,0xc7,0xf5,0x31,0xac,0x11,0x9c,0x06,0xd2,0x76,0xe6,0xf5,0x4e,0x43,0x0b,0xc5,0xf8},
    {0xd0,0x4d,0xc1,0x21,0x10,0x55,0xad,0xe6,0x1b,0x46,0xf1,0x4b,0xb5,0x13,0xb2,0x55,0x23,0xc6,0x1a,0x76,0xd1,0xf7,0x0d,0x49,0x64,0xd9,0xae,0x40,0x66,0x7c,0x07,0x68},
    {0x71,0x01,0x1f,0x12,0x99,0x71,0x86,0xcf,0x3c,0x49,0xc5,0x2a,0x7c,0x41,0x7e,0x2d,0x28,0x15,0x4b,0x83,0xc5,0x1f,0xff,0xba,0x31,0x4d,0x66,0x1d,0x44,0x17,0xd9,0xc4},
};
static const RelocationSpec AtomicReferenceRelocations[] = {
    {0x86,0x87,0x8b,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0xec,0xed,0xf1,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x110,0x111,0x115,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x14d,0x14e,0x152,RelocationKind::RelativeCall,"_if_flt_monitor_unbusy",nullptr,0},
    {0x155,0x156,0x15a,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x170,0x171,0x175,RelocationKind::RelativeCall,"_if_flt_monitor_unbusy",nullptr,0},
    {0x178,0x179,0x17d,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x185,0x186,0x18a,RelocationKind::RelativeCall,"_IORWLockRead","_lck_rw_lock_shared",0},
    {0x1f2,0x1f3,0x1f7,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x26d,0x26e,0x272,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x299,0x29a,0x29e,RelocationKind::RelativeCall,"_if_proto_free",nullptr,0},
    {0x317,0x318,0x31c,RelocationKind::RelativeCall,"_IOLockLock","_lck_mtx_lock",0},
    {0x323,0x324,0x328,RelocationKind::RelativeCall,"_thread_wakeup_prim",nullptr,0},
    {0x32b,0x32c,0x330,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
};
static const RelocationSpec AtomicReferenceMapped[] = {
    {0x2de,0x2df,0x2e3,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e3,0x2e6,0x2ea,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2ea,0x2ed,0x2f1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2f6,0x2f7,0x2fb,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2fe,0x2ff,0x303,RelocationKind::RelativeCall,nullptr,nullptr,0},
};
static const uint8_t AtomicReferenceAcquire[] = {0x8b,0x4f,0x78,0x83,0xe1,0x07,0xb8,0x66,0x00,0x00,0x00,0x83,0xf9,0x02,0x0f,0x85,0x0c,0x02,0x00,0x00,0x41,0x89,0xf5,0x4c,0x8d,0x77,0x7c,0x8b,0x57,0x7c,0x85,0xd2,0x0f,0x84,0xfa,0x01,0x00,0x00,0x89,0xd1,0x8d,0x51,0x01,0x89,0xc8,0xf0,0x41,0x0f,0xb1,0x16,0x89,0xc2,0xb8,0x66,0x00,0x00,0x00,0x75,0xe3};
static const uint8_t AtomicReferenceCallback[] = {0x48,0x8b,0x7d,0xd0,0x48,0x8b,0x87,0x60,0x02,0x00,0x00,0x48,0x85,0xc0,0x74,0x0d,0x48,0x8b,0x75,0xc0,0x48,0x8b,0x55,0xb8,0xff,0xd0};
static const uint8_t AtomicReferenceRelease[] = {0xb9,0xff,0xff,0xff,0xff,0xf0,0x0f,0xc1,0x0b,0x85,0xc9,0x0f,0x84,0xb2,0x00,0x00,0x00,0x83,0xf9,0x01,0x0f,0x84};

struct Check { size_t offset; const uint8_t *bytes; size_t size; };
static const Check MutexInlineChecks[] = {
    {0x42,MutexInlineAcquire,sizeof(MutexInlineAcquire)},
    {0x256,MutexInlineCallback,sizeof(MutexInlineCallback)},
    {0x298,MutexInlineRelease,sizeof(MutexInlineRelease)}
};
static const Check MutexMonitorChecks[] = {
    {0x44,MutexMonitorAcquire,sizeof(MutexMonitorAcquire)},
    {0x1d7,MutexMonitorCallback,sizeof(MutexMonitorCallback)},
    {0x219,MutexMonitorRelease,sizeof(MutexMonitorRelease)}
};
static const Check AtomicReferenceChecks[] = {
    {0x32,AtomicReferenceAcquire,sizeof(AtomicReferenceAcquire)},
    {0x1f7,AtomicReferenceCallback,sizeof(AtomicReferenceCallback)},
    {0x238,AtomicReferenceRelease,sizeof(AtomicReferenceRelease)}
};
struct Descriptor {
    const char *name;
    size_t bodyBytes, returnOffset;
    const uint8_t *digest;
    const RelocationSpec *relocations;
    size_t relocationCount;
    const RelocationSpec *mapped;
    size_t mappedCount;
    const Check *checks;
    size_t checkCount;
    const uint8_t (*additionalDigests)[32] = nullptr;
    size_t additionalDigestCount = 0;
};
// macOS 15.1 build 24B83 official full-OTA BootKC candidate.
// No build/version gate is part of admission: the complete normalized body,
// symbol targets, mapped segment targets, and semantic byte checks are required.
// Named dependencies are the ifnet mutex lock/unlock, in-flight waiter wakeup,
// and protocol-list shared/exclusive lock APIs. Anonymous mapped references
// include dlil panic/source-string sites and local release/dispatch helpers;
// their bytes remain in the digest, while mapped validation checks permissions.
static const uint8_t MutexInlineExpandedDigest[32] = {
    0x41,0x9d,0xf2,0x07,0xf2,0x79,0x43,0xa7,0x8e,0x21,0x93,0xc5,0xbe,0x29,0xb2,0xaa,
    0x41,0x94,0xef,0x24,0xf4,0x3b,0xd1,0x55,0x2a,0xff,0x19,0xa1,0x30,0xb7,0x6c,0xea
};

static const RelocationSpec MutexInlineExpandedRelocations[] = {
    {0x3d,0x3e,0x42,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x57,0x58,0x5c,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x67,0x68,0x6c,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0xdd,0xde,0xe2,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x104,0x105,0x109,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x160,0x161,0x165,RelocationKind::RelativeCall,"_thread_wakeup_prim",nullptr,0},
    {0x169,0x16a,0x16e,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x176,0x177,0x17b,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x1d9,0x1da,0x1de,RelocationKind::RelativeCall,"_thread_wakeup_prim",nullptr,0},
    {0x1e2,0x1e3,0x1e7,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
    {0x1ef,0x1f0,0x1f4,RelocationKind::RelativeCall,"_IORWLockRead","_lck_rw_lock_shared",0},
    {0x251,0x252,0x256,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0},
    {0x2ba,0x2bb,0x2bf,RelocationKind::RelativeCall,"_IORWLockUnlock","_lck_rw_done",0}
};

static const RelocationSpec MutexInlineExpandedMapped[] = {
    {0x193,0x196,0x19a,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x19a,0x19d,0x1a1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x1a6,0x1a7,0x1ab,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x29b,0x29c,0x2a0,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e6,0x2e7,0x2eb,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x324,0x327,0x32b,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x32b,0x32e,0x332,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x337,0x338,0x33c,RelocationKind::RelativeCall,nullptr,nullptr,0}
};

static const uint8_t MutexInlineExpandedAcquire[21] = {
    0x8b,0x43,0x78,0x83,0xe0,0x07,0x83,0xf8,0x02,0x0f,0x85,0x22,0x01,0x00,0x00,0xff,
    0x43,0x7c,0x4c,0x89,0xf7
};
static const uint8_t MutexInlineExpandedCallback[28] = {
    0x48,0x8b,0x8b,0x00,0x02,0x00,0x00,0x44,0x89,0xe0,0x48,0x85,0xc9,0x74,0x0d,0x48,
    0x89,0xdf,0x48,0x8b,0x75,0xd0,0x48,0x8b,0x55,0xc0,0xff,0xd1
};
static const uint8_t MutexInlineExpandedRelease[8] = {
    0x48,0x89,0xdf,0xe8,0xc0,0x04,0x00,0x00
};

static const Check MutexInlineExpandedChecks[] = {
    {0x042,MutexInlineExpandedAcquire,sizeof(MutexInlineExpandedAcquire)},
    {0x256,MutexInlineExpandedCallback,sizeof(MutexInlineExpandedCallback)},
    {0x298,MutexInlineExpandedRelease,sizeof(MutexInlineExpandedRelease)}
};

// The older filter-lock layout is at 0x300 rather than 0x2f8. The callback
// remains at 0x1f8, so this contract shares the existing semantic checks.
static const uint8_t MutexInlineAlternateDigest[32] = {
    0x4f,0x81,0x53,0x8b,0x5b,0x33,0x8a,0x4b,0x14,0x7e,0x49,0xb8,0xf2,0x6c,0xc3,0x07,
    0x8a,0x0f,0x09,0xfd,0xf5,0xee,0xc7,0x11,0x52,0x96,0x54,0x3c,0x7c,0x4f,0x9b,0x84
};
#define IFNET_ARRAY_COUNT(x) (sizeof(x)/sizeof((x)[0]))
static const Descriptor Additional[] = {
    {"mutex-inline",0x340,0x272,MutexInlineDigest,MutexInlineRelocations,
     IFNET_ARRAY_COUNT(MutexInlineRelocations),MutexInlineMapped,
     IFNET_ARRAY_COUNT(MutexInlineMapped),MutexInlineChecks,IFNET_ARRAY_COUNT(MutexInlineChecks)},
    {"mutex-monitor",0x2d0,0x1f1,MutexMonitorDigest,MutexMonitorRelocations,
     IFNET_ARRAY_COUNT(MutexMonitorRelocations),MutexMonitorMapped,
     IFNET_ARRAY_COUNT(MutexMonitorMapped),MutexMonitorChecks,IFNET_ARRAY_COUNT(MutexMonitorChecks)},
    {"atomic-reference",0x340,0x211,AtomicReferenceDigest,AtomicReferenceRelocations,
     IFNET_ARRAY_COUNT(AtomicReferenceRelocations),AtomicReferenceMapped,
     IFNET_ARRAY_COUNT(AtomicReferenceMapped),AtomicReferenceChecks,IFNET_ARRAY_COUNT(AtomicReferenceChecks),
     AtomicReferenceAdditionalDigests,IFNET_ARRAY_COUNT(AtomicReferenceAdditionalDigests)},
    {"mutex-inline-alternate",0x340,0x272,MutexInlineAlternateDigest,MutexInlineRelocations,
     IFNET_ARRAY_COUNT(MutexInlineRelocations),MutexInlineMapped,
     IFNET_ARRAY_COUNT(MutexInlineMapped),MutexInlineChecks,IFNET_ARRAY_COUNT(MutexInlineChecks)},
    {"mutex-inline-expanded",0x340,0x272,MutexInlineExpandedDigest,MutexInlineExpandedRelocations,
     IFNET_ARRAY_COUNT(MutexInlineExpandedRelocations),MutexInlineExpandedMapped,
     IFNET_ARRAY_COUNT(MutexInlineExpandedMapped),MutexInlineExpandedChecks,IFNET_ARRAY_COUNT(MutexInlineExpandedChecks)}
};
constexpr size_t AdditionalCount=IFNET_ARRAY_COUNT(Additional);
constexpr size_t MaxRelocations=16;
#undef IFNET_ARRAY_COUNT

inline Status validate(const Descriptor &profile,const uint8_t *bytes,size_t size,uintptr_t base,
                       const Relocation *relocations,size_t count,IfnetIoctlPlan &plan) {
    plan={};
    if (!bytes || !base || !profile.digest || !profile.checks || !profile.checkCount ||
        !profile.bodyBytes || profile.bodyBytes>MaxContractBytes ||
        profile.additionalDigestCount>16 ||
        (profile.additionalDigestCount && !profile.additionalDigests) ||
        !profile.returnOffset || profile.returnOffset>=profile.bodyBytes ||
        base>UINTPTR_MAX-profile.bodyBytes) return Status::InvalidInput;
    if (size!=profile.bodyBytes) return Status::Truncated;
    if (!sameRelocationLayout(relocations,count,profile.relocations,profile.relocationCount))
        return Status::InvalidRelocation;
    uint8_t digest[32];
    const auto status=normalizedSha256(bytes,size,base,relocations,count,digest);
    if (status!=Status::Passed) return status;
    bool recognized=equalDigest(digest,profile.digest);
    for (size_t i=0;!recognized && i<profile.additionalDigestCount;++i)
        recognized=equalDigest(digest,profile.additionalDigests[i]);
    if (!recognized) return Status::FingerprintMismatch;
    for (size_t i=0;i<profile.checkCount;++i) {
        const auto &check=profile.checks[i];
        if (!matches(bytes,size,check.offset,check.bytes,check.size)) return Status::SemanticMismatch;
    }
    plan.imageBase=base;plan.callbackReturnPC=base+profile.returnOffset;
    plan.imageSpan=size;plan.proofTag=IfnetPlanProof;
    return Status::Passed;
}
inline Status validateMapped(const Descriptor &profile,const uint8_t *bytes,size_t size,uintptr_t base,
                             MappedTargetValidator validator,void *context) {
    if (!validator || size!=profile.bodyBytes || !profile.mapped || !profile.mappedCount)
        return Status::InvalidInput;
    for (size_t i=0;i<profile.mappedCount;++i) {
        const auto &spec=profile.mapped[i];uintptr_t target=0;
        const auto status=relativeTargetAt(bytes,size,base,spec,target);
        if (status!=Status::Passed) return status;
        if (!validator(spec.kind,target,context)) return Status::SemanticMismatch;
    }
    return Status::Passed;
}
inline bool knownPlan(const IfnetIoctlPlan &plan) {
    if (plan.proofTag!=IfnetPlanProof || !plan.imageBase ||
        plan.imageBase>UINTPTR_MAX-plan.imageSpan) return false;
    if (plan.imageSpan==IfnetIoctlContractBytes &&
        plan.callbackReturnPC==plan.imageBase+0x211) return true;
    for (size_t i=0;i<AdditionalCount;++i) {
        const auto &p=Additional[i];
        if (plan.imageSpan==p.bodyBytes &&
            plan.callbackReturnPC==plan.imageBase+p.returnOffset) return true;
    }
    return false;
}
} // namespace IfnetProfiles
} // namespace KernelContracts
#endif
