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
struct ClientMemoryPlan {
    uintptr_t imageBase = 0;
    size_t bodyBytes = 0;
    size_t routeBytes = 0;
    uint32_t proofTag = 0;
};

constexpr uint32_t IfnetPlanProof = 0x49464E31U; // IFN1
constexpr uint32_t ClientMemoryPlanProof = 0x434D5531U; // CMU1

// SHA-256 of the complete current 25G332 function body after only the listed
// PC-relative call/RIP displacements are zeroed and independently resolved.
// A different UUID/build is eligible only if its complete function contract
// matches one of the independently inspected layouts below. Provenance is in
// validation/compatibility-contracts.json; unknown bytes fail closed.
static const uint8_t IfnetCurrentDigest[32] = {
    0xb2,0x29,0x1b,0x21,0x49,0xc4,0x49,0xaa,0x29,0x5d,0xc2,0xfb,0x1a,0x42,0x53,0x6c,
    0xa8,0x5c,0xed,0x69,0x87,0xf1,0xfb,0x1c,0x5d,0x5e,0x35,0x33,0x76,0xaa,0xcb,0x01
};
// Legacy exact-layout alternatives are retained for the saved evidence set.
// Their anonymous target displacements remain part of these digests.
static const uint8_t IfnetCurrentAdditionalDigests[][32] = {
    {0x04,0x9a,0x9c,0x63,0xfd,0x08,0x04,0xb1,0x70,0xd3,0x72,0xb1,0xdc,0x04,0xa2,0x44,0x2a,0x3e,0xb8,0xcd,0x24,0x0e,0xc7,0xf7,0x23,0x64,0xed,0x17,0x14,0xa4,0x03,0xae},
    {0x32,0x86,0x2c,0x6c,0x9a,0x99,0xc7,0x2e,0x17,0x6e,0x16,0x53,0x02,0x24,0xa3,0x24,0x84,0xb4,0x65,0x1a,0x41,0xee,0x54,0xa1,0xd4,0xfd,0xb7,0x8f,0x38,0x32,0x0f,0xbd},
    {0xbf,0xaf,0xf5,0xf9,0xe2,0x65,0x66,0x4d,0xe3,0xb7,0xc3,0x26,0x07,0x69,0x80,0x8d,0xd5,0xc3,0xa7,0x0d,0xb5,0x10,0xc6,0x25,0xe3,0xb0,0x71,0xf4,0xc4,0x75,0x61,0xf0},
    {0x6a,0x54,0x9a,0x79,0x5e,0x5d,0x01,0x24,0xa9,0x16,0xf2,0xdd,0x8b,0x33,0x2c,0x6e,0xd7,0xd1,0x03,0xa8,0xd0,0xcf,0x21,0xde,0x40,0xf1,0x01,0xad,0x08,0xb6,0xaa,0x54},
    {0xa1,0x27,0xee,0x3d,0x27,0x9f,0xad,0x14,0x3d,0xee,0x9a,0x5f,0xfb,0x32,0x74,0xac,0xb3,0x61,0x3c,0x9b,0x17,0x44,0x6e,0x35,0x4b,0xf4,0xf5,0x43,0x0e,0xd6,0xd3,0x9f},
    {0x65,0xe7,0xc7,0xcf,0xf8,0xfd,0x6c,0xdc,0xb9,0x68,0x26,0xf1,0xe8,0x37,0xf6,0x33,0xfb,0x40,0x20,0x23,0x2c,0x99,0x79,0x9c,0xaf,0x3f,0xe6,0x1a,0x5d,0x6e,0x76,0x64},
};
// A separate bounded digest set is admitted only after bounded target reads
// prove the five cold-path helpers and literals below. The 0x377 call target
// remains in the digest: its nearby symbol name and shared prefix are not
// enough to establish that callee's meaning.
static const uint8_t IfnetCurrentSemanticDigest[32] = {
    0xa7,0xcd,0x86,0xf6,0xe2,0xd5,0x53,0xda,0xd3,0xaa,0xed,0xba,0xe7,0x55,0xa9,0x90,
    0x36,0xa4,0x9a,0xef,0x53,0xa2,0x1a,0xea,0xfa,0x7d,0x37,0x20,0xd1,0x0c,0x6c,0x04
};
static const uint8_t IfnetCurrentSemanticAdditionalDigests[][32] = {
    {0x6e,0x04,0x93,0x94,0x48,0xc3,0x70,0x40,0x3e,0x39,0x8d,0xaa,0x64,0xf6,0x67,0x38,0xdd,0x58,0x4f,0xa9,0x9f,0xec,0x96,0x1b,0xb3,0xd9,0xcc,0xb8,0x6b,0xa9,0xb8,0x4b},
    {0x02,0x42,0x0c,0x30,0xb0,0x1a,0xdd,0x01,0xc4,0x40,0xa4,0x48,0x57,0x8b,0xf0,0x2b,0xdc,0x8e,0x3b,0x76,0x97,0x97,0x3b,0xd1,0x5d,0x3a,0xf0,0x6c,0x3d,0xa8,0xe0,0x65},
    {0xa6,0x4c,0x83,0x5d,0xbb,0x94,0x51,0x7d,0x04,0x50,0xbe,0x20,0xcb,0x4b,0x02,0x0a,0x7f,0xda,0xdf,0xbb,0x2d,0xc0,0xfc,0x28,0x9a,0x35,0xab,0x5e,0x3f,0x58,0x76,0x59},
    {0xba,0x62,0xa7,0xfc,0xb3,0x68,0xa8,0xdc,0x48,0x89,0xc2,0x71,0x11,0xb4,0xaf,0x8c,0x83,0x1c,0xd5,0x58,0xa9,0xd3,0x5b,0xd2,0xc8,0x83,0xdd,0x32,0xb8,0xc3,0x80,0x83},
    {0x90,0xa3,0xac,0xbb,0xdd,0x69,0x06,0xf5,0x39,0x54,0x19,0xef,0x38,0x31,0xd2,0x63,0x23,0xaa,0xcd,0xc5,0x8d,0x6c,0xb6,0x3e,0x63,0x20,0xef,0x53,0x72,0x62,0xf7,0xe5},
    {0xf3,0x42,0x7a,0x33,0x4a,0x8d,0x88,0x03,0xc3,0xbc,0x50,0x2a,0xd5,0xa0,0xe1,0x30,0xb3,0xbe,0xcc,0xe3,0x25,0x49,0x56,0xd9,0x05,0x5a,0xa8,0x42,0x99,0xbf,0xbd,0x0b}
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

// The legacy route checks these six cold panic/string references for mapping
// and retains every displacement in its digest. The semantic route separately
// validates five helper/string targets before normalizing those five operands;
// 0x377 stays in both digest routes because its callee meaning is unproven.
static const RelocationSpec IfnetMappedTargetSpecs[] = {
    {0x2de,0x2df,0x2e3,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e3,0x2e6,0x2ea,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2ea,0x2ed,0x2f1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2f6,0x2f7,0x2fb,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2fe,0x2ff,0x303,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x377,0x378,0x37c,RelocationKind::RelativeCall,nullptr,nullptr,0}
};

static const char IfnetSemanticPanicSymbol[] = "_panic";
// These five targets are dynamic only after their literal/helper contents pass
// validateIfnetCurrentTargetSemantics. Keep the six-entry legacy table above
// unchanged so exact digest replay remains byte-for-byte compatible.
static const RelocationSpec IfnetCurrentSemanticTargetSpecs[] = {
    {0x2de,0x2df,0x2e3,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2e3,0x2e6,0x2ea,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2ea,0x2ed,0x2f1,RelocationKind::RipRelative,nullptr,nullptr,0},
    {0x2f6,0x2f7,0x2fb,RelocationKind::RelativeCall,nullptr,nullptr,0},
    {0x2fe,0x2ff,0x303,RelocationKind::RelativeCall,nullptr,nullptr,0}
};
constexpr size_t IfnetCurrentDynamicRelocationCount=
    sizeof(IfnetRelocationSpecs)/sizeof(IfnetRelocationSpecs[0]);
constexpr size_t IfnetCurrentSemanticTargetCount=
    sizeof(IfnetCurrentSemanticTargetSpecs)/sizeof(IfnetCurrentSemanticTargetSpecs[0]);
constexpr size_t IfnetCurrentSemanticRelocationCount=
    IfnetCurrentDynamicRelocationCount+IfnetCurrentSemanticTargetCount;

constexpr size_t IfnetRelocationCount = sizeof(IfnetRelocationSpecs) / sizeof(IfnetRelocationSpecs[0]);
constexpr size_t IfnetMappedTargetCount = sizeof(IfnetMappedTargetSpecs) / sizeof(IfnetMappedTargetSpecs[0]);

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

inline bool fixedIfnetCurrentDynamicRelocationLayout(const Relocation *relocations,size_t count);
inline Status validateIfnetIoctl(const uint8_t *bytes,size_t size,uintptr_t base,
                                 const Relocation *relocations,size_t relocationCount,
                                 const uint8_t expectedDigest[32],IfnetIoctlPlan &plan);

// Semantic fallback evidence is copied only from a target reached by a
// checked instruction in the bounded _ifnet_ioctl/helper bodies. Production's
// reader additionally checks the running kernel's Mach-O segment and performs
// a no-fault wired-memory copy. The verifier supplies an equivalent bounded
// record reader for saved image excerpts.
constexpr size_t MaxIfnetSemanticEvidenceRead = 256;
using IfnetSemanticEvidenceReader = bool (*)(uintptr_t address,uint8_t *destination,
                                              size_t size,bool executable,void *context);

inline bool readIfnetSemanticCString(IfnetSemanticEvidenceReader reader,void *context,
                                     uintptr_t address,const char *exact,
                                     const char *prefix,const char *suffix) {
    if (!reader || !address || (!exact && !prefix && !suffix)) return false;
    uint8_t bytes[MaxIfnetSemanticEvidenceRead] {};
    if (!reader(address,bytes,sizeof(bytes),false,context)) return false;
    size_t length=0;
    while (length<sizeof(bytes) && bytes[length]) ++length;
    if (length==sizeof(bytes)) return false;
    if (exact && (strlen(exact)!=length || memcmp(bytes,exact,length))) return false;
    if (prefix) {
        const size_t prefixLength=strlen(prefix);
        if (length<prefixLength || memcmp(bytes,prefix,prefixLength)) return false;
    }
    if (suffix) {
        const size_t suffixLength=strlen(suffix);
        if (length<suffixLength || memcmp(bytes+length-suffixLength,suffix,suffixLength)) return false;
    }
    return true;
}

struct IfnetMaskedByteRange { size_t offset; size_t size; };
inline bool matchesIfnetHelperCode(const uint8_t *actual,size_t size,const uint8_t *expected,
                                   const IfnetMaskedByteRange *masked,size_t maskedCount) {
    if (!actual || !expected || (maskedCount && !masked)) return false;
    for (size_t i=0;i<size;++i) {
        bool ignored=false;
        for (size_t j=0;j<maskedCount;++j) {
            const auto &range=masked[j];
            if (range.offset>size || range.size>size-range.offset) return false;
            if (i>=range.offset && i-range.offset<range.size) { ignored=true;break; }
        }
        if (!ignored && actual[i]!=expected[i]) return false;
    }
    return true;
}

inline uint32_t readIfnetSemanticU32(const uint8_t *bytes,size_t offset) {
    return uint32_t(bytes[offset]) | (uint32_t(bytes[offset+1])<<8U) |
           (uint32_t(bytes[offset+2])<<16U) | (uint32_t(bytes[offset+3])<<24U);
}

inline Status validateIfnetPanicFormatter(uintptr_t target,uintptr_t panicTarget,
                                          IfnetSemanticEvidenceReader reader,void *context) {
    static const uint8_t expected[] = {
        0x55,0x48,0x89,0xe5,0x89,0xd1,0x48,0x89,0xf2,0x48,0x89,0xfe,0x48,0x8d,0x3d,
        0,0,0,0,0x4c,0x8d,0x05,0,0,0,0,0x41,0xb9,0,0,0,0,0x31,0xc0,0xe8,0,0,0,0
    };
    static const IfnetMaskedByteRange masked[]={{0x0f,4},{0x16,4},{0x1c,4},{0x23,4}};
    uint8_t code[sizeof(expected)] {};
    if (!reader || !target || !panicTarget ||
        !reader(target,code,sizeof(code),true,context) ||
        !matchesIfnetHelperCode(code,sizeof(code),expected,masked,sizeof(masked)/sizeof(masked[0])))
        return Status::SemanticMismatch;
    const uint32_t line=readIfnetSemanticU32(code,0x1c);
    if (!line || line>0xffffU) return Status::SemanticMismatch;

    uintptr_t format=0,source=0,panic=0;
    static const RelocationSpec formatSpec={0x0c,0x0f,0x13,RelocationKind::RipRelative,nullptr,nullptr,0};
    static const RelocationSpec sourceSpec={0x13,0x16,0x1a,RelocationKind::RipRelative,nullptr,nullptr,0};
    static const RelocationSpec panicSpec={0x22,0x23,0x27,RelocationKind::RelativeCall,nullptr,nullptr,0};
    if (relativeTargetAt(code,sizeof(code),target,formatSpec,format)!=Status::Passed ||
        relativeTargetAt(code,sizeof(code),target,sourceSpec,source)!=Status::Passed ||
        relativeTargetAt(code,sizeof(code),target,panicSpec,panic)!=Status::Passed || panic!=panicTarget ||
        !readIfnetSemanticCString(reader,context,format,"assertion failed: %s, file: %s, line: %d @%s:%d",nullptr,nullptr) ||
        !readIfnetSemanticCString(reader,context,source,"uipc_socket.c",nullptr,nullptr))
        return Status::SemanticMismatch;
    return Status::Passed;
}

inline Status validateIfnetRefcountHelper(uintptr_t target,uintptr_t panicTarget,
                                          IfnetSemanticEvidenceReader reader,void *context,
                                          bool overflow) {
    static const uint8_t overflowCode[] = {
        0x55,0x48,0x89,0xe5,0x48,0x89,0xfe,0x8b,0x17,0x48,0x8d,0x3d,0,0,0,0,
        0x4c,0x8d,0x05,0,0,0,0,0xb9,0xff,0xff,0xff,0x0f,0x41,0xb9,0,0,0,0,
        0x31,0xc0,0xe8,0,0,0,0
    };
    static const uint8_t underflowCode[] = {
        0x55,0x48,0x89,0xe5,0x48,0x89,0xfe,0x48,0x8d,0x3d,0,0,0,0,
        0x48,0x8d,0x15,0,0,0,0,0xb9,0,0,0,0,0x31,0xc0,0xe8,0,0,0,0
    };
    static const IfnetMaskedByteRange overflowMasked[]={{0x0c,4},{0x13,4},{0x1e,4},{0x25,4}};
    static const IfnetMaskedByteRange underflowMasked[]={{0x0a,4},{0x11,4},{0x16,4},{0x1d,4}};
    const uint8_t *expected=overflow?overflowCode:underflowCode;
    const size_t size=overflow?sizeof(overflowCode):sizeof(underflowCode);
    const auto *masked=overflow?overflowMasked:underflowMasked;
    const size_t maskedCount=overflow?sizeof(overflowMasked)/sizeof(overflowMasked[0]):
                                      sizeof(underflowMasked)/sizeof(underflowMasked[0]);
    uint8_t code[sizeof(overflowCode)] {};
    if (!reader || !target || !panicTarget ||
        !reader(target,code,size,true,context) ||
        !matchesIfnetHelperCode(code,size,expected,masked,maskedCount))
        return Status::SemanticMismatch;
    const uint32_t line=readIfnetSemanticU32(code,overflow?0x1e:0x16);
    if (!line || line>0xffffU) return Status::SemanticMismatch;

    uintptr_t format=0,source=0,panic=0;
    const RelocationSpec formatSpec=overflow ?
        RelocationSpec{0x09,0x0c,0x10,RelocationKind::RipRelative,nullptr,nullptr,0} :
        RelocationSpec{0x07,0x0a,0x0e,RelocationKind::RipRelative,nullptr,nullptr,0};
    const RelocationSpec sourceSpec=overflow ?
        RelocationSpec{0x10,0x13,0x17,RelocationKind::RipRelative,nullptr,nullptr,0} :
        RelocationSpec{0x0e,0x11,0x15,RelocationKind::RipRelative,nullptr,nullptr,0};
    const RelocationSpec panicSpec=overflow ?
        RelocationSpec{0x24,0x25,0x29,RelocationKind::RelativeCall,nullptr,nullptr,0} :
        RelocationSpec{0x1c,0x1d,0x21,RelocationKind::RelativeCall,nullptr,nullptr,0};
    const char *formatText=overflow ? "os_refcnt: overflow (rc=%p, count=%u, max=%u) @%s:%d" :
                                      "os_refcnt: underflow (rc=%p) @%s:%d";
    if (relativeTargetAt(code,size,target,formatSpec,format)!=Status::Passed ||
        relativeTargetAt(code,size,target,sourceSpec,source)!=Status::Passed ||
        relativeTargetAt(code,size,target,panicSpec,panic)!=Status::Passed || panic!=panicTarget ||
        !readIfnetSemanticCString(reader,context,format,formatText,nullptr,nullptr) ||
        !readIfnetSemanticCString(reader,context,source,"refcnt.c",nullptr,nullptr))
        return Status::SemanticMismatch;
    return Status::Passed;
}

inline Status validateIfnetCurrentTargetSemantics(const uint8_t *bytes,size_t size,uintptr_t base,
                                                  uintptr_t panicTarget,
                                                  IfnetSemanticEvidenceReader reader,void *context) {
    if (!bytes || !base || !panicTarget || !reader) return Status::InvalidInput;
    if (size!=IfnetIoctlContractBytes) return Status::Truncated;
    uintptr_t overflow=0,busyMessage=0,sourcePath=0,assertion=0,underflow=0;
    for (size_t i=0;i<IfnetCurrentSemanticTargetCount;++i) {
        const auto &spec=IfnetCurrentSemanticTargetSpecs[i];
        uintptr_t target=0;
        const Status status=relativeTargetAt(bytes,size,base,spec,target);
        if (status!=Status::Passed) return status;
        switch (spec.instructionOffset) {
            case 0x2de: overflow=target;break;
            case 0x2e3: busyMessage=target;break;
            case 0x2ea: sourcePath=target;break;
            case 0x2f6: assertion=target;break;
            case 0x2fe: underflow=target;break;
            default: return Status::InvalidRelocation;
        }
    }
    if (!overflow || !busyMessage || !sourcePath || !assertion || !underflow ||
        !readIfnetSemanticCString(reader,context,busyMessage,"ifp->if_flt_busy != 0",nullptr,nullptr) ||
        !readIfnetSemanticCString(reader,context,sourcePath,nullptr,"/AppleInternal/","/Sources/xnu/bsd/net/dlil_subr.c"))
        return Status::SemanticMismatch;
    Status status=validateIfnetRefcountHelper(overflow,panicTarget,reader,context,true);
    if (status!=Status::Passed) return status;
    status=validateIfnetPanicFormatter(assertion,panicTarget,reader,context);
    if (status!=Status::Passed) return status;
    return validateIfnetRefcountHelper(underflow,panicTarget,reader,context,false);
}

inline Status validateIfnetCurrentSemantic(const uint8_t *bytes,size_t size,uintptr_t base,
                                           const Relocation *relocations,size_t relocationCount,
                                           uintptr_t panicTarget,IfnetSemanticEvidenceReader reader,
                                           void *context,IfnetIoctlPlan &plan) {
    plan={};
    if (!fixedIfnetCurrentDynamicRelocationLayout(relocations,relocationCount))
        return Status::InvalidRelocation;
    const Status semantic=validateIfnetCurrentTargetSemantics(
        bytes,size,base,panicTarget,reader,context);
    if (semantic!=Status::Passed) return semantic;
    Relocation ownedRelocations[IfnetCurrentSemanticRelocationCount] {};
    memcpy(ownedRelocations,relocations,IfnetCurrentDynamicRelocationCount*sizeof(Relocation));
    for (size_t i=0;i<IfnetCurrentSemanticTargetCount;++i) {
        const auto &spec=IfnetCurrentSemanticTargetSpecs[i];
        uintptr_t target=0;
        const Status targetStatus=relativeTargetAt(bytes,size,base,spec,target);
        if (targetStatus!=Status::Passed) return targetStatus;
        ownedRelocations[IfnetCurrentDynamicRelocationCount+i]={
            spec.instructionOffset,spec.displacementOffset,spec.instructionEndOffset,target,spec.kind};
    }
    Status status=validateIfnetIoctl(bytes,size,base,ownedRelocations,
        IfnetCurrentSemanticRelocationCount,IfnetCurrentSemanticDigest,plan);
    for (size_t i=0;status==Status::FingerprintMismatch &&
         i<sizeof(IfnetCurrentSemanticAdditionalDigests)/sizeof(IfnetCurrentSemanticAdditionalDigests[0]);++i)
        status=validateIfnetIoctl(bytes,size,base,ownedRelocations,
            IfnetCurrentSemanticRelocationCount,IfnetCurrentSemanticAdditionalDigests[i],plan);
    return status;
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
inline bool copyIfnetCurrentDynamicRelocationSpecs(RelocationSpec *out,size_t count) {
    if (!out || count!=IfnetCurrentDynamicRelocationCount) return false;
    for (size_t i=0;i<IfnetRelocationCount;++i) out[i]=IfnetRelocationSpecs[i];
    return true;
}
inline bool fixedIfnetCurrentDynamicRelocationLayout(const Relocation *relocations,size_t count) {
    return count==IfnetCurrentDynamicRelocationCount &&
           fixedIfnetRelocationLayout(relocations,count);
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
    auto status=validateIfnetIoctl(bytes, size, base, relocations, relocationCount,
                                  IfnetCurrentDigest, plan);
    for (size_t i=0;status==Status::FingerprintMismatch &&
        i<sizeof(IfnetCurrentAdditionalDigests)/sizeof(IfnetCurrentAdditionalDigests[0]);++i)
        status=validateIfnetIoctl(bytes,size,base,relocations,relocationCount,
                                 IfnetCurrentAdditionalDigests[i],plan);
    return status;
}

} // namespace KernelContracts
#endif
