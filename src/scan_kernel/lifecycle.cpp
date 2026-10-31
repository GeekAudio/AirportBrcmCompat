// Custom Lilu bootstrap plus an observer which remains visible on refusal.
// Compile instead of Lilu's Library/plugin_start.cpp, with both CUSTOM macros.
#include <Headers/plugin_start.hpp>
#include <Headers/kern_api.hpp>
#include <IOKit/IOLib.h>
#include <libkern/c++/OSDictionary.h>
#include <libkern/c++/OSNumber.h>
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSData.h>
#include <kern/clock.h>
#include "../private_mac_compat/root_credential.hpp"
#endif
#include "diagnostics.hpp"
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
#include "../awdl_kernel/baseline_trace.hpp"
#endif
#include "kernel_identity.hpp"
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
#include "../awdl_kernel/native_control_bridge.hpp"
#include "../awdl_kernel/scoped_reset.hpp"
#endif

#if !defined(LILU_CUSTOM_KMOD_INIT) || !defined(LILU_CUSTOM_IOKIT_INIT)
#error "lifecycle.cpp requires LILU_CUSTOM_KMOD_INIT and LILU_CUSTOM_IOKIT_INIT"
#endif

extern PluginConfiguration ADDPR(config);
bool ADDPR(startSuccess) = false;
bool ADDPR(debugEnabled) = false;
uint32_t ADDPR(debugPrintDelay) = 0;

class EXPORT PRODUCT_NAME : public IOService {
    OSDeclareDefaultStructors(PRODUCT_NAME)
public:
    IOService *probe(IOService *provider, SInt32 *score) override;
    bool start(IOService *provider) override;
    void stop(IOService *provider) override;
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
    IOReturn setProperties(OSObject *) override;
#endif
#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
    bool serializeProperties(OSSerialize *serialize) const override;
#endif
};
OSDefineMetaClassAndStructors(PRODUCT_NAME, IOService)

namespace {
// State may be recorded before I/O Kit creates the observer. Atomic scalars
// retain those early outcomes; the observer never gates callback registration.
int32_t stageCodes[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1
};
const char *const stageNames[] = {
    "Bootstrap", "Access", "ShouldLoad", "PluginInit", "BuildGuard", "RuntimeBuild",
    "Provider", "Legacy", "Symbols", "Guards", "ScanRoute",
    "CapabilitiesRoute", "FirstConverted", "FirstPending", "FirstCapability",
    "AssociationSymbols", "AssociationGuards", "CopyInRoute", "AssociationRoute",
    "AssociationValidation", "AssociationField", "FirstAssociationCopy", "AssociationResult",
    "PrivatePins", "PrivateKernelCaller", "PrivateBSDRoute", "PrivateDriverRoute",
    "PrivateAuthRoute", "PrivateReady", "PrivateEntry", "PrivateGateReason", "PrivateGateField",
    "PrivateApplyStage", "PrivateApplyResult", "PrivateBackendStatus", "FirstPrivateApplied",
    "PrivatePostResult", "PrivateQuarantined", "AssociationFlags24",
    "AssociationByte469", "PrivateDhcpAllowedRequest",
    "AuthLowerLow16",
    "AuthLowerHigh16",
    "AuthUpperLow16",
    "AuthUpperHigh16",
    "AllowedAuthLow16",
    "AllowedAuthHigh16",
    "ColocatedScopeLengthLow16",
    "ColocatedScopeLengthHigh16",
    "AuthUpperExtLow16",
    "AuthUpperExtHigh16",
    "TransitionDisabledLow16",
    "TransitionDisabledHigh16",
    "BandPreferenceLow16",
    "BandPreferenceHigh16",
    "WSecFlagsLow16",
    "WSecFlagsHigh16",
    "SixGPolicy",
    "DenyListedBSSIDCount",
    "SecondIELength",
    "UnknownTailFirstOffset",
    "UnknownTailNonzero",
    "ColocatedScopeFallbackGuard",
    "PrivateGatePhase",
    "PrivateGateObservedMask",
    "PrivateGateMainLow16",
    "PrivateGateMainHigh16",
    "PrivateGateMainRole",
    "PrivateGateAssocLow16",
    "PrivateGateAssocHigh16",
    "PrivateGateScan",
    "MultipleSymbols", "MultipleGuards", "MultipleRoute", "MultipleValidation",
    "MultipleField", "MultipleCopy", "MultipleResult",
    "KeyLengthLow16", "KeyLengthHigh16", "CipherLow16", "CipherHigh16",
    "PmkLengthLow16", "PmkLengthHigh16", "FirstIELength"
};
static_assert(sizeof(stageCodes) / sizeof(stageCodes[0]) == ScanDiagnostics::StageCount,
              "Every diagnostic stage needs an initial sentinel");
static_assert(sizeof(stageNames) / sizeof(stageNames[0]) == ScanDiagnostics::StageCount,
              "Every diagnostic stage needs a stable name");
uint32_t resolvedSymbols = 0;
uint32_t generation = 1;
uint32_t publishedGeneration = 0;
bool pluginInitEntered = false;
bool pluginInitReturned = false;
bool observerEverStarted = false;
IOLock *observerLock = nullptr;
// Protected by observerLock. The global reference is retained until stop;
// publication holds the same lock, so stop cannot free a publishing object.
PRODUCT_NAME *observer = nullptr;

bool addNumber(OSDictionary *dictionary, const char *key, uint32_t value) {
    OSNumber *number = OSNumber::withNumber(value, 32);
    if (!number) return false;
    bool result = dictionary->setObject(key, number);
    number->release();
    return result;
}
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
bool addWideNumber(OSDictionary *d,const char *key,uint64_t value) {
    OSNumber *number=OSNumber::withNumber(value,64);
    if (!number) return false;
    const bool result=d->setObject(key,number);number->release();return result;
}
uint64_t observationClock() {
    uint64_t ticks=0,ns=0;clock_get_uptime(&ticks);absolutetime_to_nanoseconds(ticks,&ns);return ns;
}
bool appendWindowSample(const AWDLKernel::BaselineTrace::WindowSample &s,void *context) {
    auto *rows=static_cast<OSArray *>(context);
    OSDictionary *d=OSDictionary::withCapacity(40);if (!d) return false;
    bool valid=true;
#define SAMPLE(member,key) valid &= addNumber(d,key,s.member)
    valid &= addWideNumber(d,"CaptureNs",s.captureNs);
    valid &= addNumber(d,"SourceAliasLow32",static_cast<uint32_t>(s.sourceAlias));
    valid &= addNumber(d,"SourceAliasHigh32",static_cast<uint32_t>(s.sourceAlias>>32));
    SAMPLE(sequence,"Sequence");SAMPLE(pool,"Pool");SAMPLE(subtype,"Subtype");SAMPLE(parseFlags,"ParseFlags");
    SAMPLE(receiveChannelRaw,"ReceiveChannelRaw");SAMPLE(receiveChannelFlagsRaw,"ReceiveChannelFlagsRaw");
    SAMPLE(sourceComparable,"SourceComparable");SAMPLE(sourceMatchesLocal,"SourceMatchesLocal");
    SAMPLE(advertisedLocalComparable,"AdvertisedLocalComparable");SAMPLE(advertisedMatchesLocal,"AdvertisedMatchesLocal");
    SAMPLE(summary.lastLength,"Length");SAMPLE(summary.lastTlvCount,"TlvCount");
    SAMPLE(summary.lastTlv4HasNextChannel,"HasNextChannel");SAMPLE(summary.lastTlv4NextChannel,"NextChannel");
    SAMPLE(summary.lastTlv4HasTxDownCounter,"HasTxDownCounter");SAMPLE(summary.lastTlv4TxDownCounter,"TxDownCounterTu");
    SAMPLE(summary.lastTlv4HasMasterChannel,"HasMasterChannel");SAMPLE(summary.lastTlv4MasterChannel,"MasterChannel");
    SAMPLE(summary.lastTlv4HasAwSequence,"HasAwSequence");SAMPLE(summary.lastTlv4AwSequence,"AwSequence");
    SAMPLE(summary.lastTlv4PresenceFieldsAvailable,"HasPresenceFields");
    SAMPLE(summary.lastTlv4MinExt,"MinExt");SAMPLE(summary.lastTlv4MaxExtMulticast,"MaxExtMulticast");
    SAMPLE(summary.lastTlv4MaxExtUnicast,"MaxExtUnicast");SAMPLE(summary.lastTlv4MaxExtActionFrame,"MaxExtActionFrame");
    SAMPLE(summary.lastTlv4PresenceModeAvailable,"HasPresenceMode");SAMPLE(summary.lastTlv4PresenceMode,"PresenceMode");
    SAMPLE(summary.lastTlv12FlagsWordAvailable,"AddressFlagsWordAvailable");
    SAMPLE(summary.lastTlv12Flags,"AddressFlags");SAMPLE(summary.lastTlv12UnclassifiedFlagBits,"UnclassifiedAddressFlags");
    SAMPLE(summary.lastTlv12AwdlAddressAdvertised,"AddressAdvertised");
    SAMPLE(summary.lastTlv12AwdlAddressPrefixComparable,"AddressPrefixComparable");
    SAMPLE(summary.lastTlv12AwdlAddressPrefixMatchesMetadataSource,"AddressPrefixMatchesSource");
    SAMPLE(summary.lastTlv18HeaderAvailable,"HasChannelSequence");SAMPLE(summary.lastTlv18ChannelCount,"ChannelCount");
    SAMPLE(summary.lastTlv18Encoding,"ChannelEncoding");SAMPLE(summary.lastTlv18DuplicateCount,"ChannelDuplicateCount");
    SAMPLE(summary.lastTlv18StepCount,"ChannelStepCount");SAMPLE(summary.lastTlv18FillChannel,"ChannelFill");
#undef SAMPLE
    if (valid) valid=rows->setObject(d);d->release();return valid;
}
bool addControlWindow(OSDictionary *all) {
    using namespace AWDLKernel::BaselineTrace;
    const auto s=windowSnapshot();
    OSDictionary *d=OSDictionary::withCapacity(40);OSArray *rows=OSArray::withCapacity(SampleLimit);
    if (!d || !rows) {if (d) d->release();if (rows) rows->release();return false;}
    bool valid=true;
#define WINDOW(member,key) valid &= addNumber(d,key,s.member)
    WINDOW(schema,"Schema");WINDOW(state,"State");WINDOW(generation,"Generation");
    WINDOW(windowsUsed,"WindowsUsed");WINDOW(windowLimit,"WindowLimit");WINDOW(durationSeconds,"DurationSeconds");
    WINDOW(sampleCapacity,"SampleCapacity");WINDOW(observations,"Observations");WINDOW(thinned,"Thinned");
    WINDOW(droppedCapacity,"DroppedCapacity");WINDOW(afterDeadline,"AfterDeadline");WINDOW(clockRejected,"ClockRejected");
    WINDOW(inFlightBefore,"InFlightBefore");WINDOW(inFlightAfter,"InFlightAfter");WINDOW(closed,"Closed");
#undef WINDOW
    valid &= addNumber(d,"ClockKind",1); // mach_absolute_time scaled ns; excludes sleep.
    valid &= addNumber(d,"ControlRxOnly",1);valid &= addNumber(d,"ReceiveChannelIsAbiRaw",1);
    valid &= addWideNumber(d,"StartNs",s.startNs);valid &= addWideNumber(d,"EndNs",s.endNs);
    valid &= addWideNumber(d,"ObservedNs",s.observedNs);
    const char *reserved[]={"PsfReserved","MifReserved","OtherReserved"};
    const char *ready[]={"PsfReady","MifReady","OtherReady"};
    const char *pending[]={"PsfPending","MifPending","OtherPending"};
    const char *first[]={"PsfFirstNs","MifFirstNs","OtherFirstNs"};
    const char *last[]={"PsfLastNs","MifLastNs","OtherLastNs"};
    for (unsigned j=0;j<3;j++) {
        valid &= addNumber(d,reserved[j],s.reserved[j]);valid &= addNumber(d,ready[j],s.ready[j]);
        valid &= addNumber(d,pending[j],s.pending[j]);valid &= addWideNumber(d,first[j],s.firstNs[j]);
        valid &= addWideNumber(d,last[j],s.lastNs[j]);
    }
    if (valid && s.generation) valid=visitWindowSamples(s,appendWindowSample,rows);
    if (valid) valid=d->setObject("Samples",rows) && all->setObject("BroadcomAwdlControlRxWindow",d);
    rows->release();d->release();return valid;
}
#endif
void changed() {
    __atomic_add_fetch(&generation, 1U, __ATOMIC_RELEASE);
    ScanDiagnostics::publish();
}
}

namespace ScanDiagnostics {
void recordBatch(const Entry *entries,size_t count) {
    if (!entries || !count || count>static_cast<size_t>(StageCount)) return;
    for (size_t j=0;j<count;j++)
        if (entries[j].stage<Bootstrap || entries[j].stage>=StageCount) return;
    bool modified=false;
    for (size_t j=0;j<count;j++) {
        const int32_t previous=__atomic_exchange_n(&stageCodes[entries[j].stage],entries[j].code,__ATOMIC_ACQ_REL);
        modified|=previous!=entries[j].code;
    }
    if (modified) changed();
}
void record(Stage stage, int32_t result) {
    const Entry entry {stage,result};recordBatch(&entry,1);
}
void symbolMask(uint32_t mask) {
    mask &= 63U;
    uint32_t previous = __atomic_exchange_n(&resolvedSymbols, mask, __ATOMIC_ACQ_REL);
    if (previous != mask) changed();
}
void publish() {
    if (!observerLock) return;
    IOLockLock(observerLock);
    const uint32_t snapshotGeneration = __atomic_load_n(&generation, __ATOMIC_ACQUIRE);
    if (!observer || snapshotGeneration == publishedGeneration) {
        IOLockUnlock(observerLock);
        return;
    }
    // One replacement property publishes a complete snapshot. Allocation
    // failures retain the previous snapshot and leave this generation dirty.
    OSDictionary *snapshot = OSDictionary::withCapacity(StageCount + 11);
    bool valid = snapshot != nullptr;
    if (valid) {
        valid = addNumber(snapshot, "Schema", 1) &&
                addNumber(snapshot, "Generation", snapshotGeneration) &&
                addNumber(snapshot, "SymbolMask", __atomic_load_n(&resolvedSymbols, __ATOMIC_ACQUIRE));
        valid &= snapshot->setObject("BootstrapAccepted", ADDPR(startSuccess) ? kOSBooleanTrue : kOSBooleanFalse);
        valid &= snapshot->setObject("PluginInitEntered", __atomic_load_n(&pluginInitEntered, __ATOMIC_ACQUIRE) ? kOSBooleanTrue : kOSBooleanFalse);
        valid &= snapshot->setObject("PluginInitReturned", __atomic_load_n(&pluginInitReturned, __ATOMIC_ACQUIRE) ? kOSBooleanTrue : kOSBooleanFalse);
        valid &= snapshot->setObject("ObserverActive", kOSBooleanTrue);
        // Structural image validation is a prerequisite, not a statement that
        // every bridge is compatible. Each installer reports its own result.
        valid &= addNumber(snapshot,"AutomaticCompatibility",1);
        valid &= addNumber(snapshot,"KernelImageState",
            static_cast<uint32_t>(ScanKernelIdentity::currentProfile()));
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
        valid &= addNumber(snapshot,"BaselineTraceConfigured",1);
#else
        valid &= addNumber(snapshot,"BaselineTraceConfigured",0);
#endif
#if defined(AIRPORT_BRCM_SAE_COMPAT)
        valid &= addNumber(snapshot,"SaeCompatConfigured",1);
#else
        valid &= addNumber(snapshot,"SaeCompatConfigured",0);
#endif
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
        valid &= addNumber(snapshot,"ControlRxWindowsConfigured",1);
#else
        valid &= addNumber(snapshot,"ControlRxWindowsConfigured",0);
#endif
        for (int index = Bootstrap; valid && index < StageCount; ++index) {
            OSDictionary *stage = OSDictionary::withCapacity(2);
            if (!stage) { valid = false; break; }
            const int32_t code = __atomic_load_n(&stageCodes[index], __ATOMIC_ACQUIRE);
            valid = addNumber(stage, "Code", static_cast<uint32_t>(code)) &&
                    stage->setObject("Reached", code != -1 ? kOSBooleanTrue : kOSBooleanFalse) &&
                    snapshot->setObject(stageNames[index], stage);
            stage->release();
        }
        if (valid && observer->setProperty("ScanCompatDiagnostics", snapshot))
            publishedGeneration = snapshotGeneration;
        snapshot->release();
    }
    IOLockUnlock(observerLock);
}
}

IOService *PRODUCT_NAME::probe(IOService *provider, SInt32 *score) {
    setProperty("VersionInfo", xStringify(MODULE_VERSION));
    // A rejected bootstrap must still be observable. This class has no device
    // or user-client functionality, and does not register hooks in probe/start.
    return IOService::probe(provider, score);
}

bool PRODUCT_NAME::start(IOService *provider) {
    if (!IOService::start(provider)) return false;
    if (!observerLock) {
        SYSLOG("init", "diagnostic observer unavailable: lock allocation failed");
        IOService::stop(provider);
        return false;
    }
    IOLockLock(observerLock);
    if (observer) {
        IOLockUnlock(observerLock);
        IOService::stop(provider);
        return false;
    }
    retain();
    observer = this;
    publishedGeneration = 0;
    __atomic_store_n(&observerEverStarted, true, __ATOMIC_RELEASE);
    IOLockUnlock(observerLock);
    setProperty("VersionInfo", xStringify(MODULE_VERSION));
    ScanDiagnostics::publish();
    registerService();
    return true;
}

void PRODUCT_NAME::stop(IOService *provider) {
    PRODUCT_NAME *retainedObserver = nullptr;
    if (observerLock) {
        IOLockLock(observerLock);
        if (observer == this) {
            retainedObserver = observer;
            observer = nullptr;
        }
        IOLockUnlock(observerLock);
    }
    IOService::stop(provider);
    if (retainedObserver) retainedObserver->release();
}

#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
IOReturn PRODUCT_NAME::setProperties(OSObject *properties) {
    if (!PrivateMAC::currentCredentialIsRoot()) return kIOReturnNotPrivileged;
    if (ml_at_interrupt_context() || !ml_get_interrupts_enabled()) return kIOReturnNotPermitted;
    if (!AWDLKernel::NativeControlBridge::ready()) return kIOReturnNotReady;
    const auto *outer=OSDynamicCast(OSDictionary,properties);
    if (!outer || outer->getCount()!=1) return kIOReturnBadArgument;
    const auto *request=OSDynamicCast(OSDictionary,outer->getObject("AirportBrcmArmObservation"));
    if (!request || request->getCount()!=3) return kIOReturnBadArgument;
    const auto *seconds=OSDynamicCast(OSNumber,request->getObject("Seconds"));
    const auto *key=OSDynamicCast(OSData,request->getObject("AliasKey"));
    const auto *local=OSDynamicCast(OSData,request->getObject("LocalLinkAddress"));
    if (!seconds || !key || !local || key->getLength()!=16 || local->getLength()!=6 ||
        !seconds->unsigned64BitValue() || seconds->unsigned64BitValue()>120) return kIOReturnBadArgument;
    const auto result=AWDLKernel::BaselineTrace::armWindow(static_cast<uint32_t>(seconds->unsigned64BitValue()),
        static_cast<const uint8_t *>(key->getBytesNoCopy()),static_cast<const uint8_t *>(local->getBytesNoCopy()),observationClock);
    using Result=AWDLKernel::BaselineTrace::ArmResult;
    if (result==Result::Passed) return kIOReturnSuccess;
    if (result==Result::Busy) return kIOReturnBusy;
    if (result==Result::Exhausted) return kIOReturnNoResources;
    return kIOReturnBadArgument;
}
#endif

#if defined(AIRPORT_BRCM_NATIVE_CONTROL)
bool PRODUCT_NAME::serializeProperties(OSSerialize *serialize) const {
    // Query-time numeric snapshot: no property allocation or observer lock is
    // taken from driver gate/hook contexts. The registry copies its table under
    // its normal lock; this temporary dictionary never changes live properties.
    OSDictionary *all=IOService::dictionaryWithProperties();
    if (!all) return IOService::serializeProperties(serialize);
    OSDictionary *native=OSDictionary::withCapacity(26);
    if (!native) {all->release();return IOService::serializeProperties(serialize);}
    const auto values=AWDLKernel::NativeControlBridge::snapshot();
    bool valid=addNumber(native,"Schema",1);
#define NUMBER(member) valid &= addNumber(native,#member,values.member)
    NUMBER(state);NUMBER(openAttempts);NUMBER(openAuthorized);NUMBER(openSucceeded);NUMBER(openFailed);
    NUMBER(get43Attempts);NUMBER(get43Succeeded);NUMBER(query1);NUMBER(query5);NUMBER(query7);
    NUMBER(virtualTerminate);NUMBER(virtualWillTerminate);NUMBER(controllerTerminate);NUMBER(controllerStop);
    NUMBER(lastOpenResult);NUMBER(lastVersionStatus);NUMBER(lastBackendStatus);
    NUMBER(externalAttempts);NUMBER(lastSelector);NUMBER(queryShapeRejected);
#undef NUMBER
    valid &= addNumber(native,"resetReady",AWDLKernel::ScopedResetBridge::ready()?1U:0U);
    valid &= addNumber(native,"resetCompleted",AWDLKernel::ScopedResetBridge::completed());
    valid &= addNumber(native,"resetWithoutCallback",AWDLKernel::ScopedResetBridge::closedWithoutCallback());
    valid &= addNumber(native,"resetRetired",AWDLKernel::ScopedResetBridge::retired());
    if (valid) all->setObject("NativeControlDiagnostics",native);
    native->release();
#ifdef AIRPORT_BRCM_EVENT_PIPE
    OSDictionary *events=OSDictionary::withCapacity(72);
    if (events) {
        const auto event=AWDLKernel::NativeControlBridge::eventSnapshot();
        bool eventValid=addNumber(events,"Schema",1);
#define EVENT_NUMBER(member) eventValid &= addNumber(events,#member,event.member)
        EVENT_NUMBER(routesInstalled);EVENT_NUMBER(capability);EVENT_NUMBER(retiring);EVENT_NUMBER(used);
        EVENT_NUMBER(creating);EVENT_NUMBER(live);EVENT_NUMBER(closing);EVENT_NUMBER(terminal);
        EVENT_NUMBER(createAttempts);EVENT_NUMBER(createSucceeded);EVENT_NUMBER(destroyAttempts);EVENT_NUMBER(destroySucceeded);
        EVENT_NUMBER(mapAttempts);EVENT_NUMBER(mapSucceeded);EVENT_NUMBER(subscribeAttempts);EVENT_NUMBER(subscribeSucceeded);
        EVENT_NUMBER(lastResult);EVENT_NUMBER(lastMapType);EVENT_NUMBER(observerInstalled);EVENT_NUMBER(captured);
        EVENT_NUMBER(droppedShape);EVENT_NUMBER(droppedState);EVENT_NUMBER(droppedFull);EVENT_NUMBER(droppedRegistry);
        EVENT_NUMBER(callbacks);EVENT_NUMBER(committed);EVENT_NUMBER(dropped);EVENT_NUMBER(full);EVENT_NUMBER(faults);
        EVENT_NUMBER(queued);EVENT_NUMBER(running);
        EVENT_NUMBER(installStage);EVENT_NUMBER(installContext);EVENT_NUMBER(routerPrepareResult);
        EVENT_NUMBER(observerPrepareStatus);EVENT_NUMBER(observerInstallStatus);EVENT_NUMBER(memorySymbolPresent);
        EVENT_NUMBER(memoryRangeResult);EVENT_NUMBER(memoryGuardMatched);EVENT_NUMBER(memoryRouteResult);EVENT_NUMBER(installPatcherError);
        EVENT_NUMBER(observerPhase);EVENT_NUMBER(observerPinStatus);EVENT_NUMBER(observerContext);EVENT_NUMBER(observerSymbolMask);
        EVENT_NUMBER(observerCallShapeMask);EVENT_NUMBER(observerCallTargetMask);EVENT_NUMBER(observerRouteResult);EVENT_NUMBER(observerPatcherError);
        EVENT_NUMBER(received46);EVENT_NUMBER(received47);EVENT_NUMBER(received48);EVENT_NUMBER(receivedOther);
        EVENT_NUMBER(rejected46);EVENT_NUMBER(rejected47);EVENT_NUMBER(rejected48);EVENT_NUMBER(rejectedOther);
        EVENT_NUMBER(committed46);EVENT_NUMBER(committed47);EVENT_NUMBER(committed48);EVENT_NUMBER(committedOther);
        EVENT_NUMBER(lastCodecMessage);EVENT_NUMBER(lastCodecError);EVENT_NUMBER(last48RejectMask);EVENT_NUMBER(seen48RejectMask);
#undef EVENT_NUMBER
        if (eventValid) all->setObject("EventPipeDiagnostics",events);
        events->release();
    }
#endif
#if defined(AIRPORT_BRCM_BASELINE_TRACE)
    // Snapshot only on property serialization, never from an IRQ, RX hook, or
    // event-pipe publish path. These numeric fields describe bounded control
    // RX observations only; they are not control-TX or RF acknowledgements.
    if (AWDLKernel::NativeControlBridge::ready()) {
      OSDictionary *baseline=OSDictionary::withCapacity(80);
      if (baseline) {
        const auto values=AWDLKernel::BaselineTrace::snapshot();
        bool baselineValid=true;
#define BASELINE_NUMBER(member,key) baselineValid &= addNumber(baseline,"Baseline" key,values.member)
        BASELINE_NUMBER(schema,"Schema");BASELINE_NUMBER(controlRxOnly,"ControlRxOnly");
        BASELINE_NUMBER(sampleCapacity,"SampleCapacity");BASELINE_NUMBER(samplesReserved,"SamplesReserved");
        BASELINE_NUMBER(samplesReady,"SamplesReady");BASELINE_NUMBER(samplesDroppedAtCapacity,"SamplesDroppedAtCapacity");
        BASELINE_NUMBER(subtypePoolCapacity,"SubtypePoolCapacity");
        BASELINE_NUMBER(otherPoolCapacity,"OtherPoolCapacity");
        BASELINE_NUMBER(psfPoolReserved,"PsfPoolReserved");BASELINE_NUMBER(mifPoolReserved,"MifPoolReserved");
        BASELINE_NUMBER(otherPoolReserved,"OtherPoolReserved");
        BASELINE_NUMBER(psfSamplesDroppedAtCapacity,"PsfSamplesDroppedAtCapacity");
        BASELINE_NUMBER(mifSamplesDroppedAtCapacity,"MifSamplesDroppedAtCapacity");
        BASELINE_NUMBER(otherPoolSamplesDroppedAtCapacity,"OtherPoolSamplesDroppedAtCapacity");
        BASELINE_NUMBER(message48Samples,"Message48Samples");BASELINE_NUMBER(psfSamples,"PsfSamples");
        BASELINE_NUMBER(mifSamples,"MifSamples");BASELINE_NUMBER(otherSubtypeSamples,"OtherSubtypeSamples");
        BASELINE_NUMBER(malformedActionHeaderSamples,"MalformedActionHeaderSamples");
        BASELINE_NUMBER(truncatedInputSamples,"TruncatedInputSamples");
        BASELINE_NUMBER(oversizedInputSamples,"OversizedInputSamples");
        BASELINE_NUMBER(malformedTlvHeaderSamples,"MalformedTlvHeaderSamples");
        BASELINE_NUMBER(truncatedTlvValueSamples,"TruncatedTlvValueSamples");
        BASELINE_NUMBER(tlvScanLimitSamples,"TlvScanLimitSamples");
        BASELINE_NUMBER(shortKnownTlvSamples,"ShortKnownTlvSamples");
        BASELINE_NUMBER(lastLength,"LastLength");BASELINE_NUMBER(lastMetadataVersion,"LastMetadataVersion");
        BASELINE_NUMBER(lastReceiveChannel,"LastReceiveChannel");
        BASELINE_NUMBER(lastReceiveChannelFlags,"LastReceiveChannelFlags");
        BASELINE_NUMBER(lastActionVersion,"LastActionVersion");BASELINE_NUMBER(lastActionSubtype,"LastActionSubtype");
        BASELINE_NUMBER(lastActionReserved,"LastActionReserved");BASELINE_NUMBER(lastTlvCount,"LastTlvCount");
        BASELINE_NUMBER(lastTlv4Count,"LastTlv4Count");BASELINE_NUMBER(lastTlv4Length,"LastTlv4Length");
        BASELINE_NUMBER(lastTlv4HasNextChannel,"LastTlv4HasNextChannel");
        BASELINE_NUMBER(lastTlv4NextChannel,"LastTlv4NextChannel");
        BASELINE_NUMBER(lastTlv4HasTxDownCounter,"LastTlv4HasTxDownCounter");
        BASELINE_NUMBER(lastTlv4TxDownCounter,"LastTlv4TxDownCounter");
        BASELINE_NUMBER(lastTlv4HasMasterChannel,"LastTlv4HasMasterChannel");
        BASELINE_NUMBER(lastTlv4MasterChannel,"LastTlv4MasterChannel");
        BASELINE_NUMBER(lastTlv4HasAwSequence,"LastTlv4HasAwSequence");
        BASELINE_NUMBER(lastTlv4AwSequence,"LastTlv4AwSequence");
        BASELINE_NUMBER(lastTlv4PresenceFieldsAvailable,"LastTlv4PresenceFieldsAvailable");
        BASELINE_NUMBER(lastTlv4MinExt,"LastTlv4MinExt");
        BASELINE_NUMBER(lastTlv4MaxExtMulticast,"LastTlv4MaxExtMulticast");
        BASELINE_NUMBER(lastTlv4MaxExtUnicast,"LastTlv4MaxExtUnicast");
        BASELINE_NUMBER(lastTlv4MaxExtActionFrame,"LastTlv4MaxExtActionFrame");
        BASELINE_NUMBER(lastTlv4PresenceMode,"LastTlv4PresenceMode");
        BASELINE_NUMBER(lastTlv4PresenceModeAvailable,"LastTlv4PresenceModeAvailable");
        BASELINE_NUMBER(lastTlv12Count,"LastTlv12Count");BASELINE_NUMBER(lastTlv12Length,"LastTlv12Length");
        BASELINE_NUMBER(lastTlv12FlagsWordAvailable,"LastTlv12FlagsWordAvailable");
        BASELINE_NUMBER(lastTlv12Flags,"LastTlv12Flags");
        BASELINE_NUMBER(lastTlv12UnclassifiedFlagBits,"LastTlv12UnclassifiedFlagBits");
        BASELINE_NUMBER(lastTlv12AwdlAddressAdvertised,"LastTlv12AwdlAddressAdvertised");
        BASELINE_NUMBER(lastTlv12AwdlAddressPrefixComparable,"LastTlv12AwdlAddressPrefixComparable");
        BASELINE_NUMBER(lastTlv12AwdlAddressPrefixMatchesMetadataSource,"LastTlv12AwdlAddressPrefixMatchesMetadataSource");
        BASELINE_NUMBER(lastTlv18Count,"LastTlv18Count");BASELINE_NUMBER(lastTlv18Length,"LastTlv18Length");
        BASELINE_NUMBER(lastTlv18HeaderAvailable,"LastTlv18HeaderAvailable");
        BASELINE_NUMBER(lastTlv18ChannelCount,"LastTlv18ChannelCount");
        BASELINE_NUMBER(lastTlv18Encoding,"LastTlv18Encoding");
        BASELINE_NUMBER(lastTlv18DuplicateCount,"LastTlv18DuplicateCount");
        BASELINE_NUMBER(lastTlv18StepCount,"LastTlv18StepCount");
        BASELINE_NUMBER(lastTlv18FillChannel,"LastTlv18FillChannel");
        BASELINE_NUMBER(lastTlv21Count,"LastTlv21Count");BASELINE_NUMBER(lastTlv21Length,"LastTlv21Length");
        BASELINE_NUMBER(lastTlv21HeaderAvailable,"LastTlv21HeaderAvailable");
        BASELINE_NUMBER(lastTlv21Version,"LastTlv21Version");
        BASELINE_NUMBER(lastTlv21DeviceClass,"LastTlv21DeviceClass");
#undef BASELINE_NUMBER

        const auto addSubtypeSummary=[&](const char *name,
            const AWDLKernel::BaselineTrace::SubtypeSummary &value)->bool {
            OSDictionary *subtype=OSDictionary::withCapacity(48);
            if (!subtype) return false;
            bool valid=true;
#define SUBTYPE_NUMBER(member,key) valid &= addNumber(subtype,key,value.member)
            SUBTYPE_NUMBER(samples,"Samples");SUBTYPE_NUMBER(lastLength,"LastLength");
            SUBTYPE_NUMBER(lastTlvCount,"LastTlvCount");
            SUBTYPE_NUMBER(lastTlv4Count,"LastTlv4Count");
            SUBTYPE_NUMBER(lastTlv4Length,"LastTlv4Length");
            SUBTYPE_NUMBER(lastTlv4HasNextChannel,"LastTlv4HasNextChannel");
            SUBTYPE_NUMBER(lastTlv4NextChannel,"LastTlv4NextChannel");
            SUBTYPE_NUMBER(lastTlv4HasTxDownCounter,"LastTlv4HasTxDownCounter");
            SUBTYPE_NUMBER(lastTlv4TxDownCounter,"LastTlv4TxDownCounter");
            SUBTYPE_NUMBER(lastTlv4HasMasterChannel,"LastTlv4HasMasterChannel");
            SUBTYPE_NUMBER(lastTlv4MasterChannel,"LastTlv4MasterChannel");
            SUBTYPE_NUMBER(lastTlv4HasAwSequence,"LastTlv4HasAwSequence");
            SUBTYPE_NUMBER(lastTlv4AwSequence,"LastTlv4AwSequence");
            SUBTYPE_NUMBER(lastTlv4PresenceFieldsAvailable,"LastTlv4PresenceFieldsAvailable");
            SUBTYPE_NUMBER(lastTlv4MinExt,"LastTlv4MinExt");
            SUBTYPE_NUMBER(lastTlv4MaxExtMulticast,"LastTlv4MaxExtMulticast");
            SUBTYPE_NUMBER(lastTlv4MaxExtUnicast,"LastTlv4MaxExtUnicast");
            SUBTYPE_NUMBER(lastTlv4MaxExtActionFrame,"LastTlv4MaxExtActionFrame");
            SUBTYPE_NUMBER(lastTlv4PresenceMode,"LastTlv4PresenceMode");
            SUBTYPE_NUMBER(lastTlv4PresenceModeAvailable,"LastTlv4PresenceModeAvailable");
            SUBTYPE_NUMBER(lastTlv12Count,"LastTlv12Count");
            SUBTYPE_NUMBER(lastTlv12Length,"LastTlv12Length");
            SUBTYPE_NUMBER(lastTlv12FlagsWordAvailable,"LastTlv12FlagsWordAvailable");
            SUBTYPE_NUMBER(lastTlv12Flags,"LastTlv12Flags");
            SUBTYPE_NUMBER(lastTlv12UnclassifiedFlagBits,"LastTlv12UnclassifiedFlagBits");
            SUBTYPE_NUMBER(lastTlv12AwdlAddressAdvertised,"LastTlv12AwdlAddressAdvertised");
            SUBTYPE_NUMBER(lastTlv12AwdlAddressPrefixComparable,"LastTlv12AwdlAddressPrefixComparable");
            SUBTYPE_NUMBER(lastTlv12AwdlAddressPrefixMatchesMetadataSource,"LastTlv12AwdlAddressPrefixMatchesMetadataSource");
            SUBTYPE_NUMBER(lastTlv18Count,"LastTlv18Count");
            SUBTYPE_NUMBER(lastTlv18Length,"LastTlv18Length");
            SUBTYPE_NUMBER(lastTlv18HeaderAvailable,"LastTlv18HeaderAvailable");
            SUBTYPE_NUMBER(lastTlv18ChannelCount,"LastTlv18ChannelCount");
            SUBTYPE_NUMBER(lastTlv18Encoding,"LastTlv18Encoding");
            SUBTYPE_NUMBER(lastTlv18DuplicateCount,"LastTlv18DuplicateCount");
            SUBTYPE_NUMBER(lastTlv18StepCount,"LastTlv18StepCount");
            SUBTYPE_NUMBER(lastTlv18FillChannel,"LastTlv18FillChannel");
#undef SUBTYPE_NUMBER
            if (valid) valid=baseline->setObject(name,subtype);
            subtype->release();
            return valid;
        };
        baselineValid &= addSubtypeSummary("Psf",values.psf);
        baselineValid &= addSubtypeSummary("Mif",values.mif);
        if (baselineValid) all->setObject("BroadcomAwdlBaseline",baseline);
        baseline->release();
      }
    }
#endif
#if defined(AIRPORT_BRCM_BASELINE_WINDOW)
    if (AWDLKernel::NativeControlBridge::ready() && !addControlWindow(all)) {
        all->release();return false;
    }
#endif
    const bool result=all->serialize(serialize);all->release();return result;
}
#endif

EXPORT extern "C" kern_return_t ADDPR(kern_start)(kmod_info_t *, void *) {
    observerLock = IOLockAlloc();
    ScanDiagnostics::record(ScanDiagnostics::Bootstrap,
                            observerLock ? 0 : static_cast<int32_t>(LiluAPI::Error::MemoryError));
    lilu_get_boot_args("liludelay", &ADDPR(debugPrintDelay), sizeof(ADDPR(debugPrintDelay)));

    // Match Lilu's standard bootstrap exactly: never call shouldLoad or the
    // plugin while access is refused, release only an acquired access lock.
    auto error = lilu.requestAccess();
    ScanDiagnostics::record(ScanDiagnostics::Access, static_cast<int32_t>(error));
    if (error == LiluAPI::Error::NoError) {
        error = lilu.shouldLoad(ADDPR(config).product, ADDPR(config).version, ADDPR(config).runmode,
                               ADDPR(config).disableArg, ADDPR(config).disableArgNum,
                               ADDPR(config).debugArg, ADDPR(config).debugArgNum,
                               ADDPR(config).betaArg, ADDPR(config).betaArgNum,
                               ADDPR(config).minKernel, ADDPR(config).maxKernel, ADDPR(debugEnabled));
        ScanDiagnostics::record(ScanDiagnostics::ShouldLoad, static_cast<int32_t>(error));
        if (error == LiluAPI::Error::NoError && observerLock) {
            ADDPR(startSuccess) = true;
            __atomic_store_n(&pluginInitEntered, true, __ATOMIC_RELEASE);
            ScanDiagnostics::record(ScanDiagnostics::PluginInit, 0);
            ADDPR(config).pluginStart();
            __atomic_store_n(&pluginInitReturned, true, __ATOMIC_RELEASE);
            changed();
        } else if (error != LiluAPI::Error::NoError) {
            SYSLOG("init", "parent said we should not continue %d", static_cast<int>(error));
        }
        lilu.releaseAccess();
    } else {
        SYSLOG("init", "failed to call parent %d", static_cast<int>(error));
    }
    for (size_t index = 0; index < ADDPR(config).debugArgNum; ++index) {
        if (checkKernelArgument(ADDPR(config).debugArg[index])) {
            ADDPR(debugEnabled) = true;
            break;
        }
    }
    if (checkKernelArgument("-liludbgall")) ADDPR(debugEnabled) = true;

    // As in standard plugin_start.cpp, a refused bootstrap is a successful
    // module start. Unlike that implementation, its observer stays visible.
    return KERN_SUCCESS;
}

EXPORT extern "C" kern_return_t ADDPR(kern_stop)(kmod_info_t *, void *) {
    // An entered plugin may have registered callbacks even before routing.
    // An attached observer also pins this diagnostic code until reboot.
    if (__atomic_load_n(&pluginInitEntered, __ATOMIC_ACQUIRE) ||
        __atomic_load_n(&observerEverStarted, __ATOMIC_ACQUIRE)) return KERN_FAILURE;
    if (observerLock) {
        IOLockFree(observerLock);
        observerLock = nullptr;
    }
    return KERN_SUCCESS;
}
