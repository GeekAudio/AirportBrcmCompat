#ifndef SCAN_RUNTIME_BUILD_GUARD_HPP
#define SCAN_RUNTIME_BUILD_GUARD_HPP
#include <string.h>
#include "kernel_identity.hpp"

namespace ScanCompat {
// _osversion is a fixed-size kernel array, populated later by userland.
// Empty is pending, never permission to translate. Build identity must match
// the exact inner-kernel UUID profile selected by kernel_identity.cpp.
inline int runtimeBuildState(const char *value, ScanKernelIdentity::Profile profile) {
    if (!value) return 3;
    const char *expected = nullptr;
    if (profile == ScanKernelIdentity::Profile::Build25G241) expected = "25G241";
    else if (profile == ScanKernelIdentity::Profile::Build25G332) expected = "25G332";
    else return 3;
    if (!value[0]) return 1;
    // The seventh byte is the required terminator. Prefixes and unterminated
    // values can never select a profile.
    return memcmp(value, expected, 7) == 0 ? 0 : 2;
}
}
#endif
