// Read-only binding for the exact namespaced Test005 Broadcom image.
// No route registration, driver invocation, object lease or state mutation.
#ifndef SKYWALK_PRIVATE_MAC_PINNED_DRIVER_HPP
#define SKYWALK_PRIVATE_MAC_PINNED_DRIVER_HPP

#include <stddef.h>
#include <stdint.h>

namespace PrivateMAC {
struct AuthData; // station_backend.hpp: three uint32_t, version/lower/upper.

struct DriverPins {
    using SetHardwareAddress = uint32_t (*)(void *, const uint8_t *);
    using GetHardwareAddress = uint32_t (*)(void *, uint8_t *);
    using Iovar = int32_t (*)(void *, const char *, void *, uint64_t,
                             void *, uint64_t, bool, void *);
    using GetState = int32_t (*)(void *, void *, uint32_t *);
    using FindBssCfg = void *(*)(const void *, void *);
    using AssocInProgress = bool (*)(const void *);
    // Opaque const preserves the integration signature, not a no-write promise:
    // the original method may fill nested key.version in its OWN old548 copy.
    // Its argument must be writable driver-owned/legacy-handler storage, never
    // the native user SET buffer or read-only memory.
    using SetAssociate = int32_t (*)(void *, void *, const void *);
    using SetAuthType = int32_t (*)(void *, void *, const AuthData *);

    SetHardwareAddress setHardwareAddress = nullptr;
    GetHardwareAddress getHardwareAddress = nullptr;
    Iovar iovar = nullptr;
    GetState getState = nullptr;
    FindBssCfg findBssCfg = nullptr;
    AssocInProgress assocInProgress = nullptr;
    SetAssociate setAssociate = nullptr;
    SetAuthType setAuthType = nullptr;
    // Exact synchronous internal callers, for comparison only. Never log them.
    uintptr_t authCallerReturn = 0;
    uintptr_t associateCallerReturn = 0;
};

enum class DriverPinStatus : int32_t {
    Passed = 0, Input = 1, MachO = 2, UUID = 3, Text = 4, Range = 5,
    SetHardwareGuard = 10, GetHardwareGuard = 11, IovarGuard = 12,
    StateGuard = 13, FindBssGuard = 14, AssocProgressGuard = 15,
    AssociateGuard = 16, AuthGuard = 17, AuthCallerGuard = 18,
    AssociateCallerGuard = 19, FindTargetGuard = 20, MainBranchGuard = 21,
    AuthCall = 30, AssociateCall = 31, FindJump = 32
};

// imageBase must already be the readable, live Mach-O header supplied by the
// exact running kext's owner; imageSize is that owner's bounded mapped span.
// Bounds arithmetic does not discover readable VM or establish a lifetime
// lease. The caller must keep the image alive and serialize hook installation.
// Checks complete before publishing any pointer. Every failure clears out.
// Pins must be acquired before routing these entries; a trampoline is not an
// acceptable input image. No symbol-table or filesystem lookup occurs here.
DriverPinStatus initializeDriverPins(const void *imageBase, size_t imageSize,
                                     DriverPins &out);
}
#endif
