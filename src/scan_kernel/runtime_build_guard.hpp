#ifndef SCAN_RUNTIME_BUILD_GUARD_HPP
#define SCAN_RUNTIME_BUILD_GUARD_HPP
#include "kernel_identity.hpp"

namespace ScanCompat {
// This reports structural readiness only. A valid kernel Mach-O UUID is not
// an ABI allowlist; each adapter still needs its own live symbol/code/data and
// request-shape checks before it can be installed or handle a native request.
// 0: structurally ready; 1: identity pending; 3: unsupported/invalid state.
inline int runtimeBuildState(ScanKernelIdentity::Profile state) {
    if (state==ScanKernelIdentity::Profile::Structural) return 0;
    if (state==ScanKernelIdentity::Profile::Pending) return 1;
    return 3;
}
}
#endif
