#ifndef AIRPORT_BRCM_IFNET_PROFILES_HPP
#define AIRPORT_BRCM_IFNET_PROFILES_HPP
#include "kernel_contracts.hpp"

namespace KernelContracts {
// Additional independently inspected ifnet_ioctl implementations. Admission
// uses code and resolved symbols, never a kernel version or UUID. Anonymous
// references retain their displacements in the digest; they are not wildcarded.
// Provenance: official 23J631 / 24H232 BootKC samples, recorded by the offline
// verifier. These descriptors do not establish whole-system Wi-Fi support.
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
};
#define IFNET_ARRAY_COUNT(x) (sizeof(x)/sizeof((x)[0]))
static const Descriptor Additional[] = {
    {"mutex-inline",0x340,0x272,MutexInlineDigest,MutexInlineRelocations,
     IFNET_ARRAY_COUNT(MutexInlineRelocations),MutexInlineMapped,
     IFNET_ARRAY_COUNT(MutexInlineMapped),MutexInlineChecks,IFNET_ARRAY_COUNT(MutexInlineChecks)},
    {"mutex-monitor",0x2d0,0x1f1,MutexMonitorDigest,MutexMonitorRelocations,
     IFNET_ARRAY_COUNT(MutexMonitorRelocations),MutexMonitorMapped,
     IFNET_ARRAY_COUNT(MutexMonitorMapped),MutexMonitorChecks,IFNET_ARRAY_COUNT(MutexMonitorChecks)}
};
constexpr size_t AdditionalCount=IFNET_ARRAY_COUNT(Additional);
constexpr size_t MaxRelocations=16;
#undef IFNET_ARRAY_COUNT

inline Status validate(const Descriptor &profile,const uint8_t *bytes,size_t size,uintptr_t base,
                       const Relocation *relocations,size_t count,IfnetIoctlPlan &plan) {
    plan={};
    if (!bytes || !base || !profile.digest || !profile.checks || !profile.checkCount ||
        !profile.bodyBytes || profile.bodyBytes>MaxContractBytes ||
        !profile.returnOffset || profile.returnOffset>=profile.bodyBytes ||
        base>UINTPTR_MAX-profile.bodyBytes) return Status::InvalidInput;
    if (size!=profile.bodyBytes) return Status::Truncated;
    if (!sameRelocationLayout(relocations,count,profile.relocations,profile.relocationCount))
        return Status::InvalidRelocation;
    uint8_t digest[32];
    const auto status=normalizedSha256(bytes,size,base,relocations,count,digest);
    if (status!=Status::Passed) return status;
    if (!equalDigest(digest,profile.digest)) return Status::FingerprintMismatch;
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
