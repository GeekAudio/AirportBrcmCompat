#ifndef SKYWALK_SCAN_KERNEL_IDENTITY_HPP
#define SKYWALK_SCAN_KERNEL_IDENTITY_HPP

#include <stdint.h>

class KernelPatcher;

// Structurally identify the running inner kernel, not the outer KC fileset.
// Structural identity validates the bounded x86_64 Mach-O header and its
// unique nonzero UUID. It is not proof of compatibility with any private ABI;
// dependent installers must still validate their own symbols, code, and data.
// 0: structural identity; 3: allocation; 4: running-header/range acquisition;
// 5: malformed image or UUID changed during this run; 6: invalid target range.
namespace ScanKernelIdentity {
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
}

#endif
