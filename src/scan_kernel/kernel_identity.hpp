#ifndef SKYWALK_SCAN_KERNEL_IDENTITY_HPP
#define SKYWALK_SCAN_KERNEL_IDENTITY_HPP

#include <stddef.h>
#include <stdint.h>

class KernelPatcher;

// Structurally identify the running inner kernel, not the outer KC fileset.
// Structural identity validates the bounded x86_64 Mach-O header and its
// unique nonzero UUID. It is not proof of compatibility with any private ABI;
// dependent installers must still validate their own symbols, code, and data.
// 0: structural identity; 3: allocation; 4: running-header/range acquisition;
// 5: malformed image or UUID changed during this run; 6: invalid target range.
namespace ScanKernelIdentity {
// A per-admission byte budget for semantic checks that inspect a few bytes
// from already-resolved kernel targets. The copy API below charges both its
// no-fault range probe and the final copy against this budget.
enum : uint32_t {
    MaxSemanticEvidenceBytes = 8192,
    MaxSemanticEvidenceRead = 256
};
struct SemanticEvidenceBudget {
    uint32_t remaining = MaxSemanticEvidenceBytes;
};
enum class Profile : uint32_t {
    Pending = 0,
    Unsupported = 1,
    Structural = 2
};

// Called once from the patcher-ready callback. Resolve the kernel header and
// fault-free reader by symbol, without allocating framework-private objects.
int32_t initialize(KernelPatcher &patcher);

// The historic function name remains for call-site compatibility. The output
// is Structural for any well-formed x86_64 kernel image, without a build UUID
// allowlist. A UUID mismatch after the first successful observation is refused.
int32_t identifyRunningKernelProfile(Profile *profile);
Profile currentProfile();
// Copy the UUID cached by the structural check for diagnostic provenance only.
// Returns false and zeroes output before identity is established or after a
// contradictory UUID observation.
bool copyRunningKernelUUID(uint8_t uuid[16]);
int32_t verifyRunningKernelIdentity();
// Same structural UUID consistency check, plus the complete candidate range
// must fit a running executable Mach-O segment and mapped wired memory.
int32_t verifyRunningKernelCodeRange(uintptr_t address,uint64_t needed);
// Same bounded image and UUID checks, requiring the complete candidate range
// to fit a running readable Mach-O segment and mapped wired memory.
int32_t verifyRunningKernelReadableRange(uintptr_t address,uint64_t needed);
// Copy a small, caller-bounded excerpt from a target already required to lie
// in the running kernel image. This uses the resolved no-fault wired reader;
// it never directly dereferences the supplied target address.
int32_t copyRunningKernelEvidence(uintptr_t address,void *destination,size_t size,
                                  bool executable,SemanticEvidenceBudget *budget);
// Copy a bounded, caller-owned wired object through the resolved no-fault
// reader. Heap objects need not lie in a Mach-O segment. The caller must prove
// ownership and keep both ranges wired/alive and serialized for the whole copy;
// mapping alone proves none of those properties. A false result may leave a
// partial destination copy, which must be discarded. This is not a user-memory
// reader or an ownership validator for arbitrary kernel pointers.
enum : size_t { MaxOwnedWiredRead = 2048 };
bool copyOwnedWiredMemory(uintptr_t address,void *destination,size_t size);
}

#endif
