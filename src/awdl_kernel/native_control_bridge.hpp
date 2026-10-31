// Experimental control-only native endpoint. No event source or transport.
#ifndef AIRPORT_AWDL_NATIVE_CONTROL_BRIDGE_HPP
#define AIRPORT_AWDL_NATIVE_CONTROL_BRIDGE_HPP
#include <Headers/kern_patcher.hpp>
#include "client_registry.hpp"

namespace AWDLKernel { namespace NativeControlBridge {
struct Install {
    size_t legacyIndex=0,brcmIndex=0;
    mach_vm_address_t legacyAddress=0,brcmAddress=0;
    size_t legacySize=0,brcmSize=0;
    ClientRegistry *registry=nullptr;
    int (*runtimeBuild)()=nullptr;
};
enum class Status : uint32_t {
    NotInstalled=0, Input, Pins, ResetUnavailable, Routes, Ready, Retiring
};
// Pointer-free numeric snapshot. Observer/property publication stays outside
// the bridge, so no registry/object callbacks occur from these hot paths.
struct Snapshot {
    uint32_t state=0,openAttempts=0,openAuthorized=0,openSucceeded=0,openFailed=0;
    uint32_t get43Attempts=0,get43Succeeded=0,query1=0,query5=0,query7=0;
    uint32_t virtualTerminate=0,virtualWillTerminate=0,controllerTerminate=0,controllerStop=0;
    uint32_t lastOpenResult=0,lastVersionStatus=0,lastBackendStatus=0;
    uint32_t externalAttempts=0,lastSelector=0,queryShapeRejected=0;
};
// Owner has static lifetime, real loaded-image mapped extents, actual verified
// kernel/build and namespace dependencies. Installs only this pinned pair.
// All partial routes forward original trampolines until every safety route is
// ready. Normal MACF checks outside newUserClient are left intact.
void install(KernelPatcher &,const Install &);
Status status();
bool ready();
Snapshot snapshot();
struct EventSnapshot {
    uint32_t routesInstalled=0,capability=0,retiring=0,used=0,creating=0,live=0,closing=0,terminal=0;
    uint32_t createAttempts=0,createSucceeded=0,destroyAttempts=0,destroySucceeded=0;
    uint32_t mapAttempts=0,mapSucceeded=0,subscribeAttempts=0,subscribeSucceeded=0;
    uint32_t lastResult=0,lastMapType=0;
    uint32_t observerInstalled=0,captured=0,droppedShape=0,droppedState=0,droppedFull=0,droppedRegistry=0;
    uint32_t callbacks=0,committed=0,dropped=0,full=0,faults=0,queued=0,running=0;
    uint32_t installStage=0,installContext=0,routerPrepareResult=0,observerPrepareStatus=0,observerInstallStatus=0;
    uint32_t memorySymbolPresent=0,memoryRangeResult=0,memoryGuardMatched=0,memoryRouteResult=0,installPatcherError=0;
    uint32_t observerPhase=0,observerPinStatus=0,observerContext=0,observerSymbolMask=0;
    uint32_t observerCallShapeMask=0,observerCallTargetMask=0,observerRouteResult=0,observerPatcherError=0;
    uint32_t received46=0,received47=0,received48=0,receivedOther=0;
    uint32_t rejected46=0,rejected47=0,rejected48=0,rejectedOther=0;
    uint32_t committed46=0,committed47=0,committed48=0,committedOther=0;
    // Last fields come from the newest allocated resident Session with the
    // respective observation; they are not a global cross-worker timestamp.
    uint32_t lastCodecMessage=0,lastCodecError=0,last48RejectMask=0,seen48RejectMask=0;
};
// Numeric only, query-time. Large monotonic worker counts are low32bits.
EventSnapshot eventSnapshot();
// Trusted original lifecycle only. Confirms real owned registry membership,
// stops resident event admission before registry reset, and collects outside
// the captured gate where possible. No-op in the control-only build.
void markClientClosing(IOUserClient *);
void collectClient(IOUserClient *);
} } // namespace AWDLKernel::NativeControlBridge
#endif
