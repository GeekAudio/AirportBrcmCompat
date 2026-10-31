#ifndef SKYWALK_SCAN_KERNEL_IDENTITY_HPP
#define SKYWALK_SCAN_KERNEL_IDENTITY_HPP

#include <stdint.h>

// Verify the running inner kernel's immutable Mach-O UUID, not the outer KC
// fileset UUID or the late, mutable kern.osversion string. This does not replace
// the separate exact-runtime-build, Darwin version, or wireless image guards.
// 0: exact UUID; 3: allocation; 4: running-header/range acquisition; 5: UUID or
// bounded Mach-O validation failed. No kernel address is published or retained.
namespace ScanKernelIdentity {
enum class Profile : uint32_t {
    Unsupported = 0,
    Build25G241 = 1,
    Build25G332 = 2
};

// Resolve an exact compiled-in inner-kernel UUID to its build profile. A
// dual-profile build accepts only the two known UUIDs; the plugin separately
// requires the corresponding exact runtime build string before translating.
int32_t identifyRunningKernelProfile(Profile *profile);
Profile currentProfile();
int32_t verifyRunningKernelIdentity();
// Same immutable UUID proof, plus the complete candidate range must fit a
// running executable Mach-O segment. No addresses are published or retained.
int32_t verifyRunningKernelCodeRange(uintptr_t address,uint64_t needed);
}

#endif
