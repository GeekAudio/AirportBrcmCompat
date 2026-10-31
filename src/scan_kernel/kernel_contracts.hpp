#ifndef AIRPORT_BRCM_KERNEL_CONTRACTS_HPP
#define AIRPORT_BRCM_KERNEL_CONTRACTS_HPP

// Read-only, build-label-independent ABI contracts for the private kernel
// call sites used by AirportBrcmCompat. This header has no IOKit, Lilu, or
// kernel imports so its byte validators can be exercised by host tests.
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace KernelContracts {

constexpr size_t MaxContractBytes = 4096;
constexpr size_t IfnetIoctlContractBytes = 0x390;
constexpr size_t RunActionContractBytes = 0x280;
constexpr size_t ClientMemoryBodyBytes = 11;
constexpr size_t ClientMemoryRouteBytes = 9;

enum class Status : uint8_t {
    Passed = 0,
    InvalidInput,
    Truncated,
    InvalidRelocation,
    RelocationTargetMismatch,
    SemanticMismatch,
    FingerprintMismatch
};

enum class RelocationKind : uint8_t {
    RelativeCall = 1,
    RipRelative = 2
};

struct RelocationSpec {
    size_t instructionOffset;
    size_t displacementOffset;
    size_t instructionEndOffset;
    RelocationKind kind;
    const char *symbol;
    const char *alias;
    intptr_t addend;
};

// A relocation identifies the displacement operand of one instruction and
// the already-resolved kernel symbol that operand must name. Displacement
// bytes are zeroed only after the opcode shape and target are checked.
struct Relocation {
    size_t instructionOffset;
    size_t displacementOffset;
    size_t instructionEndOffset;
    uintptr_t target;
    RelocationKind kind;
};

namespace Detail {
class Sha256 {
    uint32_t state_[8];
    uint64_t bitCount_;
    uint8_t block_[64];
    size_t used_;

    static uint32_t rotateRight(uint32_t value, unsigned count) {
        return (value >> count) | (value << (32U - count));
    }
    void transform(const uint8_t *block) {
        static const uint32_t K[64] = {
            0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
            0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
            0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
            0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
            0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
            0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
            0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
            0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
        };
        uint32_t words[64];
        for (size_t i = 0; i < 16; ++i) {
            const size_t p = i * 4;
            words[i] = (uint32_t(block[p]) << 24U) | (uint32_t(block[p + 1]) << 16U) |
                       (uint32_t(block[p + 2]) << 8U) | uint32_t(block[p + 3]);
        }
        for (size_t i = 16; i < 64; ++i) {
            const uint32_t x = words[i - 15];
            const uint32_t y = words[i - 2];
            const uint32_t s0 = rotateRight(x, 7) ^ rotateRight(x, 18) ^ (x >> 3U);
            const uint32_t s1 = rotateRight(y, 17) ^ rotateRight(y, 19) ^ (y >> 10U);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }
        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];
        uint32_t e = state_[4], f = state_[5], g = state_[6], h = state_[7];
        for (size_t i = 0; i < 64; ++i) {
            const uint32_t s1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
            const uint32_t choose = (e & f) ^ (~e & g);
            const uint32_t t1 = h + s1 + choose + K[i] + words[i];
            const uint32_t s0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
            const uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
            const uint32_t t2 = s0 + majority;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
        state_[4] += e; state_[5] += f; state_[6] += g; state_[7] += h;
    }
public:
    Sha256() : state_{0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,
                       0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U},
               bitCount_(0), block_{}, used_(0) {}
    void update(uint8_t byte) {
        block_[used_++] = byte;
        bitCount_ += 8;
        if (used_ == sizeof(block_)) { transform(block_); used_ = 0; }
    }
    void finish(uint8_t output[32]) {
        const uint64_t originalBits = bitCount_;
        update(0x80);
        while (used_ != 56) update(0);
        for (int shift = 56; shift >= 0; shift -= 8) update(static_cast<uint8_t>(originalBits >> shift));
        for (size_t i = 0; i < 8; ++i) {
            output[i * 4] = static_cast<uint8_t>(state_[i] >> 24U);
            output[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16U);
            output[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8U);
            output[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
    }
};

inline bool addSigned(uintptr_t base, int32_t displacement, uintptr_t &result) {
    if (displacement >= 0) {
        const uintptr_t amount = static_cast<uintptr_t>(displacement);
        if (base > UINTPTR_MAX - amount) return false;
        result = base + amount;
    } else {
        const uintptr_t amount = static_cast<uintptr_t>(-static_cast<int64_t>(displacement));
        if (base < amount) return false;
        result = base - amount;
    }
    return true;
}

inline int32_t readSigned32(const uint8_t *bytes) {
    const uint32_t raw = uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8U) |
                         (uint32_t(bytes[2]) << 16U) | (uint32_t(bytes[3]) << 24U);
    return raw <= INT32_MAX ? static_cast<int32_t>(raw) :
        static_cast<int32_t>(static_cast<int64_t>(raw) - INT64_C(0x100000000));
}
}

inline bool equalDigest(const uint8_t left[32], const uint8_t right[32]) {
    uint8_t different = 0;
    for (size_t i = 0; i < 32; ++i) different |= static_cast<uint8_t>(left[i] ^ right[i]);
    return different == 0;
}

// Hashes the whole bounded code contract while replacing only verified,
// symbol-resolved PC-relative operands with zero. All opcodes, branch topology,
// stack/register use, field offsets, and other immediates remain in the digest.
inline Status normalizedSha256(const uint8_t *bytes, size_t size, uintptr_t base,
                               const Relocation *relocations, size_t relocationCount,
                               uint8_t digest[32]) {
    if (digest) memset(digest, 0, 32);
    if (!bytes || !digest || !base || !size || size > MaxContractBytes ||
        base > UINTPTR_MAX - size || (relocationCount && !relocations)) return Status::InvalidInput;
    for (size_t i = 0; i < relocationCount; ++i) {
        const Relocation &r = relocations[i];
        if (!r.target || r.instructionOffset >= size || r.displacementOffset > size ||
            size - r.displacementOffset < 4 || r.instructionEndOffset > size ||
            r.instructionEndOffset < r.displacementOffset + 4 ||
            r.instructionOffset >= r.displacementOffset) return Status::InvalidRelocation;
        if (r.kind == RelocationKind::RelativeCall) {
            if (r.displacementOffset != r.instructionOffset + 1 ||
                r.instructionEndOffset != r.instructionOffset + 5 || bytes[r.instructionOffset] != 0xE8)
                return Status::InvalidRelocation;
        } else if (r.kind == RelocationKind::RipRelative) {
            if (r.displacementOffset <= r.instructionOffset ||
                (bytes[r.displacementOffset - 1] & 0xC7U) != 0x05U) return Status::InvalidRelocation;
        } else return Status::InvalidRelocation;
        uintptr_t operandAddress = 0, computedTarget = 0;
        if (base > UINTPTR_MAX - r.instructionEndOffset) return Status::InvalidRelocation;
        operandAddress = base + r.instructionEndOffset;
        if (!Detail::addSigned(operandAddress, Detail::readSigned32(bytes + r.displacementOffset), computedTarget))
            return Status::InvalidRelocation;
        if (computedTarget != r.target) return Status::RelocationTargetMismatch;
        for (size_t j = 0; j < i; ++j) {
            const size_t left = r.displacementOffset, right = relocations[j].displacementOffset;
            if (left < right + 4 && right < left + 4) return Status::InvalidRelocation;
        }
    }
    Detail::Sha256 hash;
    for (size_t offset = 0; offset < size; ++offset) {
        uint8_t byte = bytes[offset];
        for (size_t i = 0; i < relocationCount; ++i) {
            const size_t begin = relocations[i].displacementOffset;
            if (offset >= begin && offset - begin < 4) { byte = 0; break; }
        }
        hash.update(byte);
    }
    hash.finish(digest);
    return Status::Passed;
}

inline bool matches(const uint8_t *bytes, size_t size, size_t offset,
                    const uint8_t *expected, size_t expectedSize) {
    return bytes && expected && offset <= size && expectedSize <= size - offset &&
           memcmp(bytes + offset, expected, expectedSize) == 0;
}

struct IfnetIoctlPlan {
    uintptr_t imageBase = 0;
    uintptr_t callbackReturnPC = 0;
    size_t imageSpan = 0;
    uint32_t proofTag = 0;
};
struct RunActionPlan {
    uintptr_t imageBase = 0;
    uintptr_t actionReturnPC = 0;
    size_t imageSpan = 0;
    uint32_t proofTag = 0;
};
struct ClientMemoryPlan {
    uintptr_t imageBase = 0;
    size_t bodyBytes = 0;
    size_t routeBytes = 0;
    uint32_t proofTag = 0;
};

constexpr uint32_t IfnetPlanProof = 0x49464E31U; // IFN1
constexpr uint32_t RunActionPlanProof = 0x52414331U; // RAC1
constexpr uint32_t ClientMemoryPlanProof = 0x434D5531U; // CMU1

// SHA-256 of the complete current 25G332 function body after only the listed
// PC-relative call/RIP displacements are zeroed and independently resolved.
// A different UUID/build is eligible only if its complete function contract
// matches; a changed body fails closed. This descriptor is not claimed to be a
// two-build fingerprint until a second raw sample is independently available.
static const uint8_t IfnetCurrentDigest[32] = {
    0xb2,0x29,0x1b,0x21,0x49,0xc4,0x49,0xaa,0x29,0x5d,0xc2,0xfb,0x1a,0x42,0x53,0x6c,
    0xa8,0x5c,0xed,0x69,0x87,0xf1,0xfb,0x1c,0x5d,0x5e,0x35,0x33,0x76,0xaa,0xcb,0x01
};
static const uint8_t RunActionCurrentDigest[32] = {
    0x21,0x08,0x61,0x39,0x88,0x8c,0xc3,0x67,0x27,0x7d,0xe4,0x87,0x40,0xbe,0x4c,0x89,
    0xe5,0x20,0x9e,0x2f,0x5a,0xea,0xd8,0x8a,0xe7,0xff,0xd7,0xbb,0x85,0x21,0x70,0xf9
};

static const RelocationSpec IfnetRelocationSpecs[] = {
    {0x086,0x087,0x08b,RelocationKind::RelativeCall,"_lck_mtx_lock_spin_always",nullptr,0},
    {0x0ec,0x0ed,0x0f1,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0},
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
    // These exact symbol+addend relationships are linker-layout anchors to
    // adjacent readable data. They do not claim the exported symbol names
    // semantic fields or a public ABI. Both sampled kernel forms must preserve
    // these exact relationships or the private capability fails closed.
    {0x355,0x357,0x35b,RelocationKind::RipRelative,"_ux_handler_port",nullptr,0x18},
    {0x363,0x366,0x36a,RelocationKind::RipRelative,"_ux_handler_port",nullptr,0x10},
    {0x37f,0x380,0x384,RelocationKind::RelativeCall,"_IOLockUnlock","_lck_mtx_unlock",0}
};

// Anonymous cold panic/string references are checked for a mapped target by
// the installer, but their displacements remain in the whole-function digest.
// A mapped target alone does not prove the target's meaning, so these bytes
// must not be normalized.
static const RelocationSpec IfnetMappedTargetSpecs[] = {
    {0x2de,0x2df,0x2e3,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e3,0x2e6,0x2ea,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2ea,0x2ed,0x2f1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2f6,0x2f7,0x2fb,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2fe,0x2ff,0x303,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x377,0x378,0x37c,RelocationKind::RelativeCall,nullptr,nullptr,0}
};

static const RelocationSpec RunActionRelocationSpecs[] = {
    {0x05d,0x060,0x064,RelocationKind::RipRelative,"_gIOKitTrace",nullptr,0},
    {0x06a,0x06c,0x074,RelocationKind::RipRelative,"_kdebug_enable",nullptr,0},
    {0x0c0,0x0c2,0x0ca,RelocationKind::RipRelative,"_kdebug_enable",nullptr,0},
    {0x1c7,0x1ca,0x1ce,RelocationKind::RipRelative,"_vm_kernel_slid_base",nullptr,0},
    {0x1d2,0x1d5,0x1d9,RelocationKind::RipRelative,"_vm_kernel_slid_top",nullptr,0},
    {0x1d9,0x1dc,0x1e0,RelocationKind::RipRelative,"_vm_kernel_slide",nullptr,0},
    {0x215,0x216,0x21a,RelocationKind::RelativeCall,"_kernel_debug",nullptr,0},
    {0x21f,0x222,0x226,RelocationKind::RipRelative,"_vm_kernel_slid_base",nullptr,0},
    {0x22a,0x22d,0x231,RelocationKind::RipRelative,"_vm_kernel_slid_top",nullptr,0},
    {0x231,0x234,0x238,RelocationKind::RipRelative,"_vm_kernel_slide",nullptr,0},
    {0x26d,0x26e,0x272,RelocationKind::RelativeCall,"_kernel_debug",nullptr,0}
};

constexpr size_t IfnetRelocationCount = sizeof(IfnetRelocationSpecs) / sizeof(IfnetRelocationSpecs[0]);
constexpr size_t IfnetMappedTargetCount = sizeof(IfnetMappedTargetSpecs) / sizeof(IfnetMappedTargetSpecs[0]);
constexpr size_t RunActionRelocationCount = sizeof(RunActionRelocationSpecs) / sizeof(RunActionRelocationSpecs[0]);

inline bool sameRelocationLayout(const Relocation *relocations, size_t count,
                                 const RelocationSpec *specs, size_t specCount) {
    if (!relocations || !specs || count != specCount) return false;
    for (size_t i = 0; i < count; ++i) {
        const auto &r = relocations[i];
        const auto &s = specs[i];
        if (r.instructionOffset != s.instructionOffset ||
            r.displacementOffset != s.displacementOffset ||
            r.instructionEndOffset != s.instructionEndOffset || r.kind != s.kind) return false;
    }
    return true;
}

inline Status relativeTargetAt(const uint8_t *bytes, size_t size, uintptr_t base,
                               const RelocationSpec &spec, uintptr_t &target) {
    target = 0;
    if (!bytes || !base || spec.instructionOffset >= size ||
        spec.displacementOffset > size || size - spec.displacementOffset < 4 ||
        spec.instructionEndOffset > size ||
        spec.instructionEndOffset < spec.displacementOffset + 4 ||
        spec.instructionOffset >= spec.displacementOffset) return Status::InvalidRelocation;
    if (spec.kind == RelocationKind::RelativeCall) {
        if (spec.displacementOffset != spec.instructionOffset + 1 ||
            spec.instructionEndOffset != spec.instructionOffset + 5 ||
            bytes[spec.instructionOffset] != 0xE8) return Status::InvalidRelocation;
    } else if (spec.kind == RelocationKind::RipRelative) {
        if ((bytes[spec.displacementOffset - 1] & 0xC7U) != 0x05U)
            return Status::InvalidRelocation;
    } else return Status::InvalidRelocation;
    if (base > UINTPTR_MAX - spec.instructionEndOffset) return Status::InvalidRelocation;
    const uintptr_t end = base + spec.instructionEndOffset;
    if (!Detail::addSigned(end, Detail::readSigned32(bytes + spec.displacementOffset), target))
        return Status::InvalidRelocation;
    return target ? Status::Passed : Status::InvalidRelocation;
}

using MappedTargetValidator = bool (*)(RelocationKind kind, uintptr_t target, void *context);
inline Status validateIfnetMappedTargets(const uint8_t *bytes,size_t size,uintptr_t base,
                                         MappedTargetValidator validator,void *context) {
    if (!bytes || !base || !validator) return Status::InvalidInput;
    for (size_t i=0;i<IfnetMappedTargetCount;++i) {
        const auto &spec=IfnetMappedTargetSpecs[i];uintptr_t target=0;
        const Status status=relativeTargetAt(bytes,size,base,spec,target);
        if (status!=Status::Passed) return status;
        if (!validator(spec.kind,target,context)) return Status::SemanticMismatch;
    }
    return Status::Passed;
}

inline bool fixedIfnetRelocationLayout(const Relocation *relocations, size_t count) {
    for (size_t i=0;i<IfnetRelocationCount;++i) if (!IfnetRelocationSpecs[i].symbol) return false;
    return sameRelocationLayout(relocations,count,IfnetRelocationSpecs,IfnetRelocationCount);
}
inline bool fixedRunActionRelocationLayout(const Relocation *relocations, size_t count) {
    for (size_t i=0;i<RunActionRelocationCount;++i) if (!RunActionRelocationSpecs[i].symbol) return false;
    return sameRelocationLayout(relocations,count,RunActionRelocationSpecs,RunActionRelocationCount);
}

// Explicit-digest variants are host-testable helpers. Production must use the
// Current wrappers below, which reject any relocation layout outside the
// compiled-in table before hashing the complete function body.
inline Status validateIfnetIoctl(const uint8_t *bytes, size_t size, uintptr_t base,
                                const Relocation *relocations, size_t relocationCount,
                                const uint8_t expectedDigest[32], IfnetIoctlPlan &plan) {
    plan = {};
    if (!bytes || !expectedDigest || !base) return Status::InvalidInput;
    if (size != IfnetIoctlContractBytes) return Status::Truncated;
    uint8_t digest[32];
    const Status hashed = normalizedSha256(bytes, size, base, relocations, relocationCount, digest);
    if (hashed != Status::Passed) return hashed;
    if (!equalDigest(digest, expectedDigest)) return Status::FingerprintMismatch;
    static const uint8_t borrowAcquire[] = {
        0x8b,0x4f,0x78,0x83,0xe1,0x07,0xb8,0x66,0x00,0x00,0x00,0x83,0xf9,0x02,
        0x0f,0x85,0x0c,0x02,0x00,0x00,0x41,0x89,0xf5,0x4c,0x8d,0x77,0x7c,0x8b,
        0x57,0x7c,0x85,0xd2,0x0f,0x84,0xfa,0x01,0x00,0x00,0x89,0xd1,0x8d,0x51,
        0x01,0x89,0xc8,0xf0,0x41,0x0f,0xb1,0x16,0x89,0xc2,0xb8,0x66,0x00,0x00,
        0x00,0x75,0xe3
    };
    static const uint8_t sourceIfnet[] = {0x48,0x89,0xfb};
    static const uint8_t saveBorrow[] = {0x4c,0x89,0x75,0xc8,0x48,0x89,0x5d,0xd0};
    static const uint8_t callback[] = {
        0x48,0x8b,0x7d,0xd0,0x48,0x8b,0x87,0x80,0x02,0x00,0x00,0x48,0x85,0xc0,
        0x74,0x0d,0x48,0x8b,0x75,0xc0,0x48,0x8b,0x55,0xb8,0xff,0xd0,0x41,0x89,
        0xc6,0x41,0x83,0xfc,0x66
    };
    static const uint8_t borrowRelease[] = {
        0xb9,0xff,0xff,0xff,0xff,0xf0,0x0f,0xc1,0x0b,0x85,0xc9,0x0f,0x84,0xb2,
        0x00,0x00,0x00,0x83,0xf9,0x01,0x0f,0x84
    };
    static const uint8_t restoreBorrowedIoref[] = {0x48,0x8b,0x5d,0xc8};
    if (!matches(bytes, size, 0x32, borrowAcquire, sizeof(borrowAcquire)) ||
        !matches(bytes, size, 0x80, sourceIfnet, sizeof(sourceIfnet)) ||
        !matches(bytes, size, 0x97, saveBorrow, sizeof(saveBorrow)) ||
        !matches(bytes, size, 0x194, restoreBorrowedIoref, sizeof(restoreBorrowedIoref)) ||
        !matches(bytes, size, 0x1f7, callback, sizeof(callback)) ||
        !matches(bytes, size, 0x238, borrowRelease, sizeof(borrowRelease))) return Status::SemanticMismatch;
    if (base > UINTPTR_MAX - 0x211) return Status::InvalidInput;
    plan.imageBase = base;
    plan.callbackReturnPC = base + 0x211;
    plan.imageSpan = size;
    plan.proofTag = IfnetPlanProof;
    return Status::Passed;
}

inline Status validateRunAction(const uint8_t *bytes, size_t size, uintptr_t base,
                                const Relocation *relocations, size_t relocationCount,
                                const uint8_t expectedDigest[32], RunActionPlan &plan) {
    plan = {};
    if (!bytes || !expectedDigest || !base) return Status::InvalidInput;
    if (size != RunActionContractBytes) return Status::Truncated;
    uint8_t digest[32];
    const Status hashed = normalizedSha256(bytes, size, base, relocations, relocationCount, digest);
    if (hashed != Status::Passed) return hashed;
    if (!equalDigest(digest, expectedDigest)) return Status::FingerprintMismatch;
    static const uint8_t ownerAndArguments[] = {
        0x49,0x8b,0x7e,0x18,0x48,0x8b,0x75,0xc8,0x48,0x8b,0x55,0xc0,
        0x48,0x8b,0x4d,0xb8,0x4c,0x8b,0x45,0xb0,0x41,0xff,0xd7
    };
    static const uint8_t savedActionAndArguments[] = {
        0x49,0x89,0xf7,0x48,0x89,0x55,0xc8,0x48,0x89,0x4d,0xc0,
        0x4c,0x89,0x45,0xb8,0x4c,0x89,0x4d,0xb0
    };
    static const uint8_t activeActionAccounting[] = {
        0x48,0xc7,0xc1,0x00,0xff,0xff,0xff,0x49,0x03,0x4e,0x48,0x49,0x89,0x4e,0x48
    };
    static const uint8_t gateAndWorkLoop[] = {
        0x49,0x89,0xfe,0x48,0x8b,0x5f,0x30,0x48,0x85,0xdb
    };
    if (!matches(bytes, size, 0x1a, gateAndWorkLoop, sizeof(gateAndWorkLoop)) ||
        !matches(bytes, size, 0x2a, savedActionAndArguments, sizeof(savedActionAndArguments)) ||
        !matches(bytes, size, 0x91, ownerAndArguments, sizeof(ownerAndArguments)) ||
        !matches(bytes, size, 0xa8, activeActionAccounting, sizeof(activeActionAccounting)))
        return Status::SemanticMismatch;
    if (base > UINTPTR_MAX - 0xa8) return Status::InvalidInput;
    plan.imageBase = base;
    plan.actionReturnPC = base + 0xa8;
    plan.imageSpan = size;
    plan.proofTag = RunActionPlanProof;
    return Status::Passed;
}

inline Status validateUnsupportedClientMemory(const uint8_t *bytes, size_t size, uintptr_t base,
                                               ClientMemoryPlan &plan) {
    plan = {};
    static const uint8_t unsupportedBody[] = {
        0x55,0x48,0x89,0xe5,0xb8,0xc7,0x02,0x00,0xe0,0x5d,0xc3
    };
    if (!bytes || !base) return Status::InvalidInput;
    if (size < sizeof(unsupportedBody)) return Status::Truncated;
    if (base > UINTPTR_MAX - sizeof(unsupportedBody)) return Status::InvalidInput;
    if (!matches(bytes, size, 0, unsupportedBody, sizeof(unsupportedBody)))
        return Status::SemanticMismatch;
    plan.imageBase = base;
    plan.bodyBytes = sizeof(unsupportedBody);
    plan.routeBytes = ClientMemoryRouteBytes;
    plan.proofTag = ClientMemoryPlanProof;
    return Status::Passed;
}

inline Status validateIfnetCurrent(const uint8_t *bytes, size_t size, uintptr_t base,
                                   const Relocation *relocations, size_t relocationCount,
                                   IfnetIoctlPlan &plan) {
    plan = {};
    if (!fixedIfnetRelocationLayout(relocations, relocationCount)) return Status::InvalidRelocation;
    return validateIfnetIoctl(bytes, size, base, relocations, relocationCount,
                              IfnetCurrentDigest, plan);
}

inline Status validateRunActionCurrent(const uint8_t *bytes, size_t size, uintptr_t base,
                                        const Relocation *relocations, size_t relocationCount,
                                        RunActionPlan &plan) {
    plan = {};
    if (!fixedRunActionRelocationLayout(relocations, relocationCount)) return Status::InvalidRelocation;
    return validateRunAction(bytes, size, base, relocations, relocationCount,
                              RunActionCurrentDigest, plan);
}

} // namespace KernelContracts
#endif
