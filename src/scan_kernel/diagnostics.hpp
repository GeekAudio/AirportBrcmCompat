#ifndef SKYWALK_SCAN_DIAGNOSTICS_HPP
#define SKYWALK_SCAN_DIAGNOSTICS_HPP

#include <stdint.h>
#include <stddef.h>

// Codes describe this plugin's control flow, never kernel pointers or hardware
// identities. -1 means not reached, 0 means success/entered, positive means a
// refusal/error. IORegistry OSNumber is unsigned: Code=0xffffffff is int32 -1;
// each stage also has a Reached boolean so consumers need not infer this.
namespace ScanDiagnostics {
enum Stage {
    Bootstrap,
    Access,
    ShouldLoad,
    PluginInit,
    BuildGuard,
    RuntimeBuild, // 0 exact build for selected UUID profile; 1 empty/not ready; 2 different; 3 unavailable.
    Provider,
    Legacy,
    Symbols,
    Guards,
    ScanRoute,
    CapabilitiesRoute,
    FirstConverted,
    FirstPending,
    FirstCapability,
    AssociationSymbols,
    AssociationGuards,
    CopyInRoute,
    AssociationRoute,
    AssociationValidation,
    AssociationField, // Offset only; never the field contents.
    FirstAssociationCopy,
    AssociationResult, // SET handler result; not RF/handshake/DHCP success.
    PrivatePins,
    PrivateKernelCaller,
    PrivateBSDRoute,
    PrivateDriverRoute,
    PrivateAuthRoute,
    PrivateReady,
    PrivateEntry,
    PrivateGateReason,
    PrivateGateField,
    PrivateApplyStage,
    PrivateApplyResult,
    PrivateBackendStatus,
    FirstPrivateApplied,
    PrivatePostResult,
    PrivateQuarantined,
    AssociationFlags24, // Only the three nonidentifying association flag bytes.
    AssociationByte469,
    PrivateDhcpAllowedRequest, // Requested permission, not effective disclosure.
    // Only bounded policy scalars/lengths; opaque identity/key carriers excluded.
    AuthLowerLow16,
    AuthLowerHigh16,
    AuthUpperLow16,
    AuthUpperHigh16,
    AllowedAuthLow16,
    AllowedAuthHigh16,
    ColocatedScopeLengthLow16,
    ColocatedScopeLengthHigh16,
    AuthUpperExtLow16,
    AuthUpperExtHigh16,
    TransitionDisabledLow16,
    TransitionDisabledHigh16,
    BandPreferenceLow16,
    BandPreferenceHigh16,
    WSecFlagsLow16,
    WSecFlagsHigh16,
    SixGPolicy,
    DenyListedBSSIDCount,
    SecondIELength,
    UnknownTailFirstOffset,
    UnknownTailNonzero,
    ColocatedScopeFallbackGuard,
    // Only scalar state from owner-derived objects under the existing gate.
    PrivateGatePhase, // 0 before original association; 1 private-MAC checks.
    PrivateGateObservedMask,
    PrivateGateMainLow16,
    PrivateGateMainHigh16,
    PrivateGateMainRole,
    PrivateGateAssocLow16,
    PrivateGateAssocHigh16,
    PrivateGateScan,
    MultipleSymbols,
    MultipleGuards,
    MultipleRoute,
    MultipleValidation,
    MultipleField,
    MultipleCopy,
    MultipleResult, // Original handler result, not hotspot association proof.
    KeyLengthLow16,
    KeyLengthHigh16,
    CipherLow16,
    CipherHigh16,
    PmkLengthLow16,
    PmkLengthHigh16,
    FirstIELength,
    StageCount
};
struct Entry { Stage stage; int32_t code; };
void recordBatch(const Entry *,size_t);

void record(Stage stage, int32_t result);
// Bits: Handler=1, Capabilities=2, Manager=4, Result=8, CopyIn=16, CopyOut=32.
void symbolMask(uint32_t mask);
// Publish only if the snapshot changed and the diagnostic IOService exists.
void publish();
}

#endif
