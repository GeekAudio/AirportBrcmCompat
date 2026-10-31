// EFI-only Lilu plugin. No system files or user processes are patched.
#include <Headers/kern_api.hpp>
#include <Headers/plugin_start.hpp>
#include <mach-o/loader.h>
#include "scan_compat.hpp"
#include "diagnostics.hpp"
#include "kernel_identity.hpp"
#include "runtime_build_guard.hpp"
#include "association_compat.hpp"
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
#include "scan_multiple_compat.hpp"
#endif
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
#include "../private_mac_compat/private_bridge.hpp"
#endif
#include <kern/thread.h>
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
#include "../awdl_kernel/native_control_bridge.hpp"
#include "../awdl_kernel/scoped_reset.hpp"
#endif
namespace {
constexpr uint8_t ProviderUUID[16]={0x03,0x5a,0x9a,0xd9,0x6c,0xde,0x36,0x2f,0x8d,0xec,0xb6,0x64,0xbc,0x64,0x31,0xec};
constexpr uint8_t LegacyUUID[16]={0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab};
constexpr const char *Handler="__ZL13getScanResultP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb";
constexpr const char *Capabilities="__ZL19getCardCapabilitiesP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb";
constexpr const char *Manager="__ZN17IO80211Controller30getPrimaryInterfaceScanManagerEv";
constexpr const char *Result="__ZN18IO80211ScanManager13getScanResultEPP22apple80211_scan_result";
constexpr const char *CopyIn="__ZN17IO80211Controller6copyInEyPvm";
constexpr const char *CopyOut="__ZN17IO80211Controller7copyOutEPKvym";
constexpr const char *Associate="__ZL19setAssociateRequestP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb";
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
constexpr const char *ScanMultiple="__ZL22setScanRequestMultipleP17IO80211ControllerP16IO80211InterfaceP23IO80211VirtualInterfaceP21IO80211InfraInterfaceP13apple80211reqb";
ScanMultipleCompat::Registry multipleRegistry {};
ScanMultipleCompat::API multipleAPI {};
bool multipleAttempted=false;
void multipleLock(void *p) {IOLockLock(static_cast<IOLock *>(p));}
void multipleUnlock(void *p) {IOLockUnlock(static_cast<IOLock *>(p));}
#endif
// Lilu KC code dereferences paths[0] even for memory-backed injected kexts.
// These are identity hints; FS fallback is not enabled.
const char *providerPaths[]={"/System/Library/Extensions/IOLegacyWFamily.kext/Contents/MacOS/IOSkywalkFamily"};
const char *legacyPaths[]={"/System/Library/Extensions/IO80211FamilyLegacy.kext/Contents/MacOS/IO80211FamilyLegacy"};
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
const char *brcmPaths[]={"/System/Library/Extensions/AirPortBrcmNIC.kext/Contents/MacOS/AirPortBrcmNIC"};
#endif
KernelPatcher::KextInfo watched[] {
    {"org.geekaudio.IOLegacyWFamilyKC",providerPaths,arrsize(providerPaths),{true}},
    {"com.apple.iokit.IO80211FamilyLegacy",legacyPaths,arrsize(legacyPaths),{true}},
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
    {"com.apple.driver.AirPort.BrcmNIC",brcmPaths,arrsize(brcmPaths),{true}},
#endif
};
bool systemVerified=false,providerVerified=false,legacyVerified=false,routingAttempted=false;
bool scanPairInstalled=false,associationAttempted=false,associationInstalled=false;
mach_vm_address_t legacyAddress=0;
size_t legacySize=0;
ScanCompat::API api {};
ScanCompat::Original originalCapabilities=nullptr;
volatile unsigned requestCount=0, successCount=0, pendingCount=0, capabilityCount=0;
volatile unsigned associationCopies=0;
AssociationCompat::Registry associationRegistry {};
AssociationCompat::API associationAPI {};
AssociationCompat::CopyIn originalCopyIn=nullptr;
uintptr_t associationOwner=0;
uintptr_t currentThreadToken() { return reinterpret_cast<uintptr_t>(current_thread()); }
void associationLock(void *lock) {
    IOLockLock(static_cast<IOLock *>(lock));
    __atomic_store_n(&associationOwner,currentThreadToken(),__ATOMIC_RELEASE);
}
void associationUnlock(void *lock) {
    __atomic_store_n(&associationOwner,uintptr_t(0),__ATOMIC_RELEASE);
    IOLockUnlock(static_cast<IOLock *>(lock));
}
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
mach_vm_address_t brcmAddress=0;size_t brcmSize=0;
uintptr_t associationLockOwner() {return __atomic_load_n(&associationOwner,__ATOMIC_ACQUIRE);}
int runtimeBuild() {
    return ScanCompat::runtimeBuildState(ScanKernelIdentity::currentProfile());
}
void observeAssociationFlags(uint32_t flags,uint8_t byte469) {
    ScanDiagnostics::record(ScanDiagnostics::AssociationFlags24,static_cast<int32_t>(flags));
    ScanDiagnostics::record(ScanDiagnostics::AssociationByte469,byte469);
}
void observeAssociationSurvey(const AssociationSurvey::Snapshot &s) {
    using namespace ScanDiagnostics;
    const Entry entries[] = {
        {AuthLowerLow16,s.authLower8.low16},{AuthLowerHigh16,s.authLower8.high16},
        {AuthUpperLow16,s.authUpper12.low16},{AuthUpperHigh16,s.authUpper12.high16},
        {AllowedAuthLow16,s.allowedAuth508.low16},{AllowedAuthHigh16,s.allowedAuth508.high16},
        {ColocatedScopeLengthLow16,s.scopeLength580.low16},{ColocatedScopeLengthHigh16,s.scopeLength580.high16},
        {AuthUpperExtLow16,s.authUpperExt624.low16},{AuthUpperExtHigh16,s.authUpperExt624.high16},
        {TransitionDisabledLow16,s.transitionDisabledFlags628.low16},{TransitionDisabledHigh16,s.transitionDisabledFlags628.high16},
        {BandPreferenceLow16,s.bandPreference632.low16},{BandPreferenceHigh16,s.bandPreference632.high16},
        {WSecFlagsLow16,s.wsecFlags636.low16},{WSecFlagsHigh16,s.wsecFlags636.high16},
        {SixGPolicy,s.sixGPolicy899},{DenyListedBSSIDCount,s.denyListedBSSIDCount518},
        {SecondIELength,s.secondIELength640},{UnknownTailFirstOffset,s.unknownTailFirstOffset},
        {UnknownTailNonzero,s.unknownTailNonzero},
        {KeyLengthLow16,s.keyLength64.low16},{KeyLengthHigh16,s.keyLength64.high16},
        {CipherLow16,s.cipher68.low16},{CipherHigh16,s.cipher68.high16},
        {PmkLengthLow16,s.pmkLength472.low16},{PmkLengthHigh16,s.pmkLength472.high16},
        {FirstIELength,s.firstIELength208}
    };
    recordBatch(entries,sizeof(entries)/sizeof(entries[0]));
}
void tryInstallPrivate(KernelPatcher &patcher) {
    if (!systemVerified || !providerVerified || !legacyVerified || !associationInstalled || !brcmAddress) return;
    PrivateBridge::Install input {watched[1].loadIndex,watched[2].loadIndex,legacyAddress,brcmAddress,
        legacySize,brcmSize,&associationRegistry,associationLockOwner,runtimeBuild};
    PrivateBridge::install(patcher,input);
}
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
AWDLKernel::ClientRegistry nativeClients;
bool nativeAttempted=false;
void tryInstallNative(KernelPatcher &patcher) {
    if (nativeAttempted || !systemVerified || !providerVerified || !legacyVerified ||
        !associationInstalled || !brcmAddress) return;
    // Install the bridge in patcher context once its target dependencies pass
    // their pins. Runtime requests still require structural kernel readiness
    // and the bridge's own ABI checks.
    nativeAttempted=true;
    if (nativeClients.prepare()!=AWDLKernel::ClientStatus::Passed ||
        !AWDLKernel::ScopedResetBridge::install(patcher,nativeClients,watched[1].loadIndex,
                                               legacyAddress,legacySize)) return;
    AWDLKernel::NativeControlBridge::Install input {watched[1].loadIndex,watched[2].loadIndex,
        legacyAddress,brcmAddress,legacySize,brcmSize,&nativeClients,runtimeBuild};
    AWDLKernel::NativeControlBridge::install(patcher,input);
}
#endif
#endif

int wrappedCopyIn(void *controller,uint64_t source,void *destination,size_t size) {
    // Capture in the actual replacement entry, before entering a helper.
    const auto caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
    const int multiple=multipleRegistry.consume(currentThreadToken(),caller,controller,source,destination,size);
    if (multiple!=-1) return multiple;
#endif
    const int result=associationRegistry.consume(currentThreadToken(),caller,controller,source,destination,size);
    if (result!=-1) return result;
    return originalCopyIn(controller,source,destination,size);
}
int wrappedAssociate(void *controller,void *interface,void *vif,void *infra,
                     ScanCompat::Request *request,bool user64) {
    const bool target=AssociationCompat::eligible(request,controller,interface,vif,infra,user64);
    if (target) {
        const int state=ScanCompat::runtimeBuildState(ScanKernelIdentity::currentProfile());
        ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,state);
        if (state) return associationAPI.original(controller,interface,vif,infra,request,user64);
    }
    AssociationCompat::Result validation {-1,0};bool consumed=false;
    const int error=AssociationCompat::handle(associationAPI,controller,interface,vif,infra,request,user64,
                                             &validation,&consumed);
    if (target) {
        if (validation.error>=0) {
            ScanDiagnostics::record(ScanDiagnostics::AssociationValidation,validation.error);
            ScanDiagnostics::record(ScanDiagnostics::AssociationField,static_cast<int32_t>(validation.field));
        }
        if (consumed && __sync_fetch_and_add(&associationCopies,1)==0)
            ScanDiagnostics::record(ScanDiagnostics::FirstAssociationCopy,0);
        // SET acceptance does not prove RF association, EAPOL, DHCP or traffic.
        ScanDiagnostics::record(ScanDiagnostics::AssociationResult,error);
    }
    return error;
}

#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
int wrappedScanMultiple(void *c,void *i,void *v,void *infra,ScanCompat::Request *r,bool user64) {
    const bool target=ScanMultipleCompat::eligible(r,c,i,v,infra,user64);
    if (target && ScanCompat::runtimeBuildState(ScanKernelIdentity::currentProfile()))
        return multipleAPI.original(c,i,v,infra,r,user64);
    ScanMultipleCompat::Result validation {-1,0};bool consumed=false;
    const int error=ScanMultipleCompat::handle(multipleAPI,c,i,v,infra,r,user64,&validation,&consumed);
    if (target) {
        if (validation.error>=0) {
            ScanDiagnostics::record(ScanDiagnostics::MultipleValidation,validation.error);
            ScanDiagnostics::record(ScanDiagnostics::MultipleField,static_cast<int32_t>(validation.field));
        }
        if (consumed) ScanDiagnostics::record(ScanDiagnostics::MultipleCopy,0);
        ScanDiagnostics::record(ScanDiagnostics::MultipleResult,error);
    }
    return error;
}
#endif

bool imageUUID(mach_vm_address_t address,size_t size,const uint8_t expected[16]) {
    if (size<sizeof(mach_header_64)) return false;
    const auto *header=reinterpret_cast<const mach_header_64 *>(address);
    if (header->magic!=MH_MAGIC_64 || header->cputype!=CPU_TYPE_X86_64 ||
        header->sizeofcmds>size-sizeof(*header) || header->ncmds>header->sizeofcmds/8) return false;
    size_t offset=sizeof(*header),end=offset+header->sizeofcmds;
    unsigned found=0;
    for (uint32_t i=0;i<header->ncmds;i++) {
        if (offset>end || end-offset<sizeof(load_command)) return false;
        const auto *cmd=reinterpret_cast<const load_command *>(address+offset);
        if (cmd->cmdsize<sizeof(load_command) || cmd->cmdsize>end-offset) return false;
        if (cmd->cmd==LC_UUID) {
            if (cmd->cmdsize!=sizeof(uuid_command) || ++found!=1 ||
                memcmp(reinterpret_cast<const uuid_command *>(cmd)->uuid,expected,16)) return false;
        }
        offset+=cmd->cmdsize;
    }
    return offset==end && found==1;
}
void *allocate(size_t size) { return IOMallocZero(size); }
void deallocate(void *data,size_t size) { IOFree(data,size); }
int wrapped(void *controller,void *interface,void *vif,void *infra,ScanCompat::Request *req,bool user64) {
    const bool native=req && req->type==11 && req->length==ScanCompat::NativeSize;
    if (native) {
        const int state=ScanCompat::runtimeBuildState(ScanKernelIdentity::currentProfile());
        ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,state);
        if (state) return api.original(controller,interface,vif,infra,req,user64);
    }
    int error=ScanCompat::handle(api,controller,interface,vif,infra,req,user64);
    if (native) {
        __sync_fetch_and_add(&requestCount,1);
        if (!error && __sync_fetch_and_add(&successCount,1)==0)
        {
            SYSLOG("scan","first native GET11 converted (nonblocking)");
            ScanDiagnostics::record(ScanDiagnostics::FirstConverted,0);
        }
        if (error==EBUSY && __sync_fetch_and_add(&pendingCount,1)==0)
        {
            SYSLOG("scan","native GET11 pending; original completion semantics retained");
            ScanDiagnostics::record(ScanDiagnostics::FirstPending,0);
        }
    }
    return error;
}
int wrappedCapabilities(void *controller,void *interface,void *vif,void *infra,
                        ScanCompat::Request *req,bool user64) {
    if (ScanCompat::nativeCapabilities(req,controller,interface,vif,infra)) {
        const int state=ScanCompat::runtimeBuildState(ScanKernelIdentity::currentProfile());
        ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,state);
        if (state) return originalCapabilities(controller,interface,vif,infra,req,user64);
    }
    bool changed=false;
    int error=ScanCompat::handleCapabilities(api,originalCapabilities,controller,interface,vif,infra,
                                            req,user64,&changed);
    if (changed && __sync_fetch_and_add(&capabilityCount,1)==0)
    {
        SYSLOG("scan","native en1 GET12 scan-event wait compatibility advertised; reply remains 12 bytes");
        ScanDiagnostics::record(ScanDiagnostics::FirstCapability,0);
    }
    return error;
}
bool within(mach_vm_address_t function,mach_vm_address_t address,size_t size,size_t needed) {
    return function>=address && function-address<=size && needed<=size-(function-address);
}
void tryInstall(KernelPatcher &patcher) {
    if (routingAttempted || !systemVerified || !providerVerified || !legacyVerified) return;
    const size_t index=watched[1].loadIndex;
    const mach_vm_address_t address=legacyAddress;
    const size_t size=legacySize;
    patcher.clearError(); // Only this symbol group's errors belong to this attempt.
    mach_vm_address_t handler=patcher.solveSymbol(index,Handler,address,size);
    mach_vm_address_t capabilities=patcher.solveSymbol(index,Capabilities,address,size);
    mach_vm_address_t manager=patcher.solveSymbol(index,Manager,address,size);
    mach_vm_address_t result=patcher.solveSymbol(index,Result,address,size);
    mach_vm_address_t copyIn=patcher.solveSymbol(index,CopyIn,address,size);
    mach_vm_address_t copyOut=patcher.solveSymbol(index,CopyOut,address,size);
    ScanDiagnostics::symbolMask((handler?1U:0U)|(capabilities?2U:0U)|(manager?4U:0U)|
                                (result?8U:0U)|(copyIn?16U:0U)|(copyOut?32U:0U));
    if (patcher.getError()!=KernelPatcher::Error::NoError ||
        !within(handler,address,size,0x56) || !within(capabilities,address,size,0xb9) || !within(manager,address,size,8) ||
        !within(result,address,size,8) || !within(copyIn,address,size,8) || !within(copyOut,address,size,8)) {
        ScanDiagnostics::record(ScanDiagnostics::Symbols,1);
        patcher.clearError(); SYSLOG("init","Legacy hook refused: unresolved/out-of-image symbol"); return;
    }
    ScanDiagnostics::record(ScanDiagnostics::Symbols,0);
    const uint8_t prologue[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53};
    const uint8_t lengthGuard[]={0xb8,0x16,0,0,0,0x81,0x7b,0x18,0x8c,0x04,0,0};
    // Include the RIP-relative load's opcode, but not its link-time rel32.
    // Lilu decodes/relocates the whole instruction when making its trampoline.
    const uint8_t capsPrologue[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x48,0x83,0xec,0x20,0x48,0x8b,0x05};
    const uint8_t capsGuard[]={0xb8,0x16,0,0,0,0x41,0x83,0x78,0x18,0};
    const uint8_t capsReply[]={0x8b,0x43,0x18,0x83,0xf8,0x0c,0xb9,0x0c,0,0,0,0x0f,0x42,0xc8,0x89,0x4b,0x18};
    if (memcmp(reinterpret_cast<const void *>(handler),prologue,sizeof(prologue)) ||
        memcmp(reinterpret_cast<const void *>(handler+0x44),lengthGuard,sizeof(lengthGuard)) ||
        memcmp(reinterpret_cast<const void *>(capabilities),capsPrologue,sizeof(capsPrologue)) ||
        memcmp(reinterpret_cast<const void *>(capabilities+0x23),capsGuard,sizeof(capsGuard)) ||
        memcmp(reinterpret_cast<const void *>(capabilities+0xa8),capsReply,sizeof(capsReply))) {
        ScanDiagnostics::record(ScanDiagnostics::Guards,1);
        SYSLOG("init","Legacy hook refused: audited handler bytes changed"); return;
    }
    ScanDiagnostics::record(ScanDiagnostics::Guards,0);
    api.allocate=allocate; api.deallocate=deallocate;
    api.manager=reinterpret_cast<decltype(api.manager)>(manager);
    api.getResult=reinterpret_cast<decltype(api.getResult)>(result);
    api.copyIn=reinterpret_cast<decltype(api.copyIn)>(copyIn);
    api.copyOut=reinterpret_cast<decltype(api.copyOut)>(copyOut);
    // Never retry a partly installed route. Each original trampoline is kept
    // independently; a failed capabilities route leaves a valid GET11-only
    // adapter and explicitly reports that the full pair was not installed.
    routingAttempted=true;
    KernelPatcher::RouteRequest route(Handler,wrapped,api.original);
    if (!patcher.routeMultiple(index,&route,1,address,size)) {
        ScanDiagnostics::record(ScanDiagnostics::ScanRoute,1);
        patcher.clearError(); SYSLOG("init","Legacy hook routing failed"); return;
    }
    ScanDiagnostics::record(ScanDiagnostics::ScanRoute,0);
    KernelPatcher::RouteRequest capsRoute(Capabilities,wrappedCapabilities,originalCapabilities);
    if (!patcher.routeMultiple(index,&capsRoute,1,address,size)) {
        ScanDiagnostics::record(ScanDiagnostics::CapabilitiesRoute,1);
        patcher.clearError();
        SYSLOG("init","GET11 active; GET12 wait compatibility routing failed (partial adapter)"); return;
    }
    ScanDiagnostics::record(ScanDiagnostics::CapabilitiesRoute,0);
    scanPairInstalled=true;
    SYSLOG("init","GET11 conversion + native GET12 scan-event wait adapter installed; no polling or worker thread");
}
void tryInstallAssociation(KernelPatcher &patcher) {
    if (associationAttempted || !scanPairInstalled || !systemVerified || !providerVerified || !legacyVerified) return;
    associationAttempted=true;
    const size_t index=watched[1].loadIndex;
    patcher.clearError();
    auto handler=patcher.solveSymbol(index,Associate,legacyAddress,legacySize);
    auto copyIn=patcher.solveSymbol(index,CopyIn,legacyAddress,legacySize);
    if (patcher.getError()!=KernelPatcher::Error::NoError ||
        !within(handler,legacyAddress,legacySize,0x153) || !within(copyIn,legacyAddress,legacySize,14)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::AssociationSymbols,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::AssociationSymbols,0);
    const uint8_t handlerGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec,0x48,0x02,0,0};
    const uint8_t copyGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x50};
    const uint8_t callGuard[]={0xe8,0xf1,0xd7,0,0,0x85,0xc0,0x0f,0x85,0x18,0x03,0,0};
    int32_t displacement=0;memcpy(&displacement,reinterpret_cast<const void *>(handler+0x147),4);
    const auto callTarget=static_cast<mach_vm_address_t>(static_cast<int64_t>(handler+0x14b)+displacement);
    if (memcmp(reinterpret_cast<const void *>(handler),handlerGuard,sizeof(handlerGuard)) ||
        memcmp(reinterpret_cast<const void *>(copyIn),copyGuard,sizeof(copyGuard)) ||
        memcmp(reinterpret_cast<const void *>(handler+0x146),callGuard,sizeof(callGuard)) || callTarget!=copyIn) {
        ScanDiagnostics::record(ScanDiagnostics::AssociationGuards,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::AssociationGuards,0);
    auto *lock=IOLockAlloc();
    if (!lock) {ScanDiagnostics::record(ScanDiagnostics::CopyInRoute,ENOMEM);return;}
    associationRegistry.lock={lock,associationLock,associationUnlock};
    associationAPI.allocate=allocate;associationAPI.deallocate=deallocate;
    associationAPI.currentThread=currentThreadToken;associationAPI.registry=&associationRegistry;
    associationAPI.caller=handler+0x14b;
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
    associationAPI.entryAllowed=PrivateBridge::entryAllowed;
    associationAPI.privateAvailable=PrivateBridge::available;
    associationAPI.observeFlags=observeAssociationFlags;
    associationAPI.observeSurvey=observeAssociationSurvey;
#endif
    KernelPatcher::RouteRequest copyRoute(CopyIn,wrappedCopyIn,originalCopyIn);
    if (!patcher.routeMultiple(index,&copyRoute,1,legacyAddress,legacySize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::CopyInRoute,1);return;
    }
    associationAPI.copyIn=originalCopyIn;
    ScanDiagnostics::record(ScanDiagnostics::CopyInRoute,0);
    KernelPatcher::RouteRequest associateRoute(Associate,wrappedAssociate,associationAPI.original);
    if (!patcher.routeMultiple(index,&associateRoute,1,legacyAddress,legacySize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::AssociationRoute,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::AssociationRoute,0);
    associationInstalled=true;
}
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
void tryInstallScanMultiple(KernelPatcher &patcher) {
    // Reuse the already verified/routed copyIn entry. Never route it twice.
    if (multipleAttempted || !associationInstalled || !originalCopyIn || !legacyVerified) return;
    multipleAttempted=true;
    const size_t index=watched[1].loadIndex;
    patcher.clearError();
    const auto handler=patcher.solveSymbol(index,ScanMultiple,legacyAddress,legacySize);
    const auto copy=patcher.solveSymbol(index,CopyIn,legacyAddress,legacySize);
    if (patcher.getError()!=KernelPatcher::Error::NoError ||
        !within(handler,legacyAddress,legacySize,0x114) || !within(copy,legacyAddress,legacySize,14)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::MultipleSymbols,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::MultipleSymbols,0);
    const uint8_t prologue[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x54,0x53,0xb8,0xf0,0x14,0,0};
    const uint8_t lengthGuard[]={0x41,0x81,0x7c,0x24,0x18,0xe0,0x14,0,0,0x75,0x70};
    const uint8_t copyGuard[]={0x48,0x8d,0x95,0xf8,0xea,0xff,0xff,0xb9,0xe0,0x14,0,0,0x4c,0x89,0xf7,0xe8,0x8e,0xad,0,0,0x85,0xc0,0x75,0x4c};
    int32_t displacement=0;memcpy(&displacement,reinterpret_cast<const void *>(handler+0x8e),4);
    const auto target=static_cast<mach_vm_address_t>(static_cast<int64_t>(handler+0x92)+displacement);
    if (memcmp(reinterpret_cast<const void *>(handler),prologue,sizeof(prologue)) ||
        memcmp(reinterpret_cast<const void *>(handler+0x69),lengthGuard,sizeof(lengthGuard)) ||
        memcmp(reinterpret_cast<const void *>(handler+0x7e),copyGuard,sizeof(copyGuard)) || target!=copy) {
        ScanDiagnostics::record(ScanDiagnostics::MultipleGuards,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::MultipleGuards,0);
    auto *lock=IOLockAlloc();
    if (!lock) {ScanDiagnostics::record(ScanDiagnostics::MultipleRoute,ENOMEM);return;}
    // CopyIn is already globally routed: publish all callback pointers before
    // any other thread may enter this registry. Published fields are immutable.
    if (!multipleRegistry.prepare({lock,multipleLock,multipleUnlock})) {
        IOLockFree(lock);ScanDiagnostics::record(ScanDiagnostics::MultipleRoute,EBUSY);return;
    }
    multipleAPI.copyIn=originalCopyIn;multipleAPI.allocate=allocate;multipleAPI.deallocate=deallocate;
    multipleAPI.currentThread=currentThreadToken;multipleAPI.registry=&multipleRegistry;
    multipleAPI.caller=handler+0x92;
    KernelPatcher::RouteRequest route(ScanMultiple,wrappedScanMultiple,multipleAPI.original);
    if (!patcher.routeMultiple(index,&route,1,legacyAddress,legacySize)) {
        patcher.clearError();ScanDiagnostics::record(ScanDiagnostics::MultipleRoute,1);return;
    }
    ScanDiagnostics::record(ScanDiagnostics::MultipleRoute,0);
    SYSLOG("init","SET86 common-prefix adapter installed; nonzero minimum timestamp is refused");
}
#endif
void loaded(KernelPatcher &patcher,size_t index,mach_vm_address_t address,size_t size) {
    if (index==watched[0].loadIndex) {
        providerVerified=imageUUID(address,size,ProviderUUID);
        ScanDiagnostics::record(ScanDiagnostics::Provider,providerVerified?0:1);
        SYSLOG("init","private provider UUID %s",providerVerified?"verified":"rejected");
    } else if (index==watched[1].loadIndex) {
        legacyVerified=imageUUID(address,size,LegacyUUID);
        ScanDiagnostics::record(ScanDiagnostics::Legacy,legacyVerified?0:1);
        if (legacyVerified) { legacyAddress=address; legacySize=size; }
        SYSLOG("init","Legacy UUID %s",legacyVerified?"verified":"rejected");
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
    } else if (index==watched[2].loadIndex) {
        // PrivateBridge validates exact UUID/ranges/bytes before any route.
        brcmAddress=address;brcmSize=size;
#endif
    }
    // The already-loaded _kmod traversal need not follow dependency order.
    tryInstall(patcher);
    tryInstallAssociation(patcher);
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
    tryInstallScanMultiple(patcher);
#endif
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
    tryInstallPrivate(patcher);
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
    tryInstallNative(patcher);
#endif
#endif
}
void init() {
    ScanDiagnostics::record(ScanDiagnostics::PluginInit,0);
    lilu.onPatcherLoadForce([](void *,KernelPatcher &patcher) {
        // Establish a bounded structural identity for the actual inner kernel.
        // This is not ABI approval: every feature installer keeps its own
        // target-image symbol, range, byte, and request-shape checks.
        ScanKernelIdentity::Profile profile=ScanKernelIdentity::Profile::Unsupported;
        const int identity=ScanKernelIdentity::identifyRunningKernelProfile(&profile);
        ScanDiagnostics::record(ScanDiagnostics::BuildGuard,identity);
        if (identity || profile!=ScanKernelIdentity::Profile::Structural) {
            watched[0].switchOff();watched[1].switchOff();
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
            watched[2].switchOff();
#endif
            SYSLOG("init","running kernel image structure rejected; no hooks installed");return;
        }
        ScanDiagnostics::record(ScanDiagnostics::RuntimeBuild,
            ScanCompat::runtimeBuildState(profile));
        systemVerified=true;
        tryInstall(patcher);
        tryInstallAssociation(patcher);
#if defined(AIRPORT_BRCM_SCAN_MULTIPLE)
        tryInstallScanMultiple(patcher);
#endif
#if defined(AIRPORT_BRCM_PRIVATE_MAC)
        tryInstallPrivate(patcher);
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
        tryInstallNative(patcher);
#endif
#endif
    });
    lilu.onKextLoadForce(watched,arrsize(watched),
        [](void *,KernelPatcher &p,size_t i,mach_vm_address_t a,size_t s) { loaded(p,i,a,s); });
}
const char *off[]={"-brcmcompatoff"};
const char *debug[]={"-brcmcompatdbg"};
}
PluginConfiguration ADDPR(config) {
    xStringify(PRODUCT_NAME),parseModuleVersion(xStringify(MODULE_VERSION)),LiluAPI::AllowNormal,
    off,arrsize(off),debug,arrsize(debug),nullptr,0,
    KernelVersion::Tahoe,static_cast<KernelVersion>(KernelPatcher::KernelAny),init
};
