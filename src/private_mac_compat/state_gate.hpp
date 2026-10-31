// Exact old-Brcm state checks only. No kernel calls, writes, allocation or lease.
// The adapter supplies genuine pinned getters and an EXISTING synchronous BSD
// call lifetime. A mapped address, OSObject retain or isInactive test is not a
// substitute. This header is not registered or connected to the live kernel.
#ifndef SKYWALK_PRIVATE_MAC_STATE_GATE_HPP
#define SKYWALK_PRIVATE_MAC_STATE_GATE_HPP
#include <stdint.h>
#include <stddef.h>

namespace PrivateMAC { namespace StateGate {
using Address=uintptr_t;
static_assert(sizeof(Address)==8,"Pinned x86_64 pointer ABI required");

enum class Reason : uint32_t {
    Passed=0, MissingBinding=1, Prerequisite=2, ReadDenied=3,
    InvalidPointer=4, ValueMismatch=5, GetterFailed=6
};
// Numeric diagnostic IDs only: a Result never contains a private pointer.
enum class Field : uint32_t {
    None=0, Pins=1, Authorization=2, LiveLease=3, Gate=4, Identity=5,
    RegistryUnlocked=6, Reader=7, Controller=8, Primary=9,
    ControllerWlc=10, ControllerPub=11, ControllerPowerSleep=12,
    ControllerPowerCycle=13, ControllerPowerState=14, WlcPub=15,
    PubOwner=16, WlcTable=17, WlcMain=18, WlcBssModule=19,
    BssModuleOwner=20, BssModuleSize=21, WlcScan=22, WlcAssocQueue=23,
    WlcGoingDown=24, WlcClock=25, PubUp=26, PubHardwareOff=27,
    PubHardwareUp=28, MainOwner=29, MainUp=30, MainEnable=31,
    MainAP=32, MainAssociated=33, MainInfra=34, MainIndex=35,
    MainAssoc=36, AssocState=37, ScanPrivate=38, ScanPubBacklink=39,
    ScanOwner=40, ScanInProgress=41, MainGetter=42, AssocHelper=43,
    StateGetter=44, StateVersion=45, StateValue=46, TableMain=47
};
struct Result {
    Reason reason;
    Field field;
    bool ok() const { return reason==Reason::Passed; }
};
// Only numeric state is exposed. A bit is set only after a bounded read and
// its following authority check both succeed. Unreached fields remain zero;
// callers must consult reached rather than infer presence from their values.
enum ObservationBit : uint16_t {
    MainUpObserved=1U<<0, MainEnableObserved=1U<<1,
    MainAPObserved=1U<<2, MainAssociatedObserved=1U<<3,
    MainInfraObserved=1U<<4, MainIndexObserved=1U<<5,
    AssocStateObserved=1U<<6, ScanInProgressObserved=1U<<7
};
struct Observation {
    uint16_t reached=0;
    uint8_t mainUp=0,mainEnable=0,mainAP=0,mainAssociated=0,mainInfra=0;
    int8_t mainIndex=0;
    uint32_t assocState=0;
    uint8_t scanInProgress=0;
};
inline Result pass() { return {Reason::Passed,Field::None}; }
inline Result fail(Reason r,Field f) { return {r,f}; }

enum class Object : uint32_t {
    Controller, Wlc, Pub, BssTable, BssModule, MainCfg, Assoc, ScanPub, ScanPrivate
};
struct Access {
    void *context=nullptr;
    // These callbacks are authority supplied by the audited adapter; they do
    // not create any new lease. They must remain non-mutating/non-blocking and
    // must not release the original workloop gate or recursively run a join.
    bool (*pins)(void *)=nullptr;
    bool (*root)(void *)=nullptr;
    bool (*liveLease)(void *,Address,Address)=nullptr;
    bool (*gateHeld)(void *,Address)=nullptr;
    bool (*identity)(void *,Address,Address)=nullptr;
    bool (*registryUnlocked)(void *)=nullptr;
    // Bounded, trusted-object reads only. extent is a verified-layout prefix,
    // not a VM probe or evidence that an arbitrary object remains allocated.
    bool (*read)(void *,Object,Address,size_t extent,size_t offset,void *,size_t)=nullptr;
    // Mandatory real pinned calls in a kernel adapter. A production callback
    // must call the actual symbol, not synthesize a result from these fields.
    bool (*mainGetter)(void *,Address controller,Address *main)=nullptr;
    bool (*assocInProgress)(void *,Address wlc,bool *busy)=nullptr;
    bool (*getState)(void *,Address controller,Address primary,uint32_t state[2])=nullptr;
    // Optional adapter proof of a CURRENT validated infrastructure request.
    // A missing/false callback preserves the old infra==1 admission rule.
    // It must inspect the genuine synchronous scope, never a user-supplied
    // permission bit, and must obey the same non-mutating callback contract.
    bool (*infrastructureJoin)(void *,Address controller,Address primary)=nullptr;
};

constexpr size_t controllerSize=0x3c10,wlcSize=0xbc0,pubSize=0x1a8;
constexpr size_t tableSize=0x80,modulePrefix=0x40,mainPrefix=0x448;
constexpr size_t assocSize=0x68,scanPubSize=0x40,scanPrivateSize=0x364;

inline Result complete(const Access &a) {
    if (!a.context) return fail(Reason::MissingBinding,Field::Reader);
    if (!a.pins) return fail(Reason::MissingBinding,Field::Pins);
    if (!a.root) return fail(Reason::MissingBinding,Field::Authorization);
    if (!a.liveLease) return fail(Reason::MissingBinding,Field::LiveLease);
    if (!a.gateHeld) return fail(Reason::MissingBinding,Field::Gate);
    if (!a.identity) return fail(Reason::MissingBinding,Field::Identity);
    if (!a.registryUnlocked) return fail(Reason::MissingBinding,Field::RegistryUnlocked);
    if (!a.read) return fail(Reason::MissingBinding,Field::Reader);
    if (!a.mainGetter) return fail(Reason::MissingBinding,Field::MainGetter);
    if (!a.assocInProgress) return fail(Reason::MissingBinding,Field::AssocHelper);
    if (!a.getState) return fail(Reason::MissingBinding,Field::StateGetter);
    return pass();
}
inline Result prerequisites(const Access &a,Address c,Address i) {
    if (!a.pins(a.context)) return fail(Reason::Prerequisite,Field::Pins);
    if (!a.root(a.context)) return fail(Reason::Prerequisite,Field::Authorization);
    if (!a.liveLease(a.context,c,i)) return fail(Reason::Prerequisite,Field::LiveLease);
    if (!a.gateHeld(a.context,c)) return fail(Reason::Prerequisite,Field::Gate);
    if (!a.identity(a.context,c,i)) return fail(Reason::Prerequisite,Field::Identity);
    if (!a.registryUnlocked(a.context)) return fail(Reason::Prerequisite,Field::RegistryUnlocked);
    return pass();
}
inline bool validPointer(Address p,size_t extent) {
    return p && !(p&7U) && extent && p<=UINTPTR_MAX-extent;
}
template<class T> inline Result readValue(const Access &a,Address c,Address i,
    Object kind,Address object,size_t extent,size_t offset,T &value,Field field) {
    Result r=prerequisites(a,c,i);if (!r.ok()) return r;
    if (!validPointer(object,extent)) return fail(Reason::InvalidPointer,field);
    if (offset>extent || sizeof(T)>extent-offset) return fail(Reason::ReadDenied,field);
    if (!a.read(a.context,kind,object,extent,offset,&value,sizeof(T)))
        return fail(Reason::ReadDenied,field);
    return prerequisites(a,c,i);
}

template<class T> inline Result readObserved(const Access &a,Address c,Address i,
    Object kind,Address object,size_t extent,size_t offset,T &value,Field field,
    Observation &observation,uint16_t bit) {
    T candidate {};
    Result r=readValue(a,c,i,kind,object,extent,offset,candidate,field);
    if (r.ok()) {value=candidate;observation.reached|=bit;}
    return r;
}

// observation, when supplied, is independently owned caller storage, never a
// part of a borrowed driver object. It does not create a new lifetime or gate.
inline Result check(const Access &a,Address c,Address i,Observation *observation=nullptr) {
    Observation local {};
    Observation &observed=observation?*observation:local;
    observed=Observation{};
    Result r=complete(a);if (!r.ok()) return r;
    if (!validPointer(c,controllerSize)) return fail(Reason::InvalidPointer,Field::Controller);
    if (!validPointer(i,sizeof(Address))) return fail(Reason::InvalidPointer,Field::Primary);
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    // The getter checks the same live interface as the original call; STATE0
    // alone is deliberately not used to infer absence of AUTH/ASSOC activity.
    uint32_t state[2] {};
    if (!a.getState(a.context,c,i,state)) return fail(Reason::GetterFailed,Field::StateGetter);
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    if (state[0]!=1) return fail(Reason::ValueMismatch,Field::StateVersion);
    if (state[1]!=0) return fail(Reason::ValueMismatch,Field::StateValue);

#define PM_STATE_READ(kind,object,bound,offset,value,field) \
    do {r=readValue(a,c,i,Object::kind,object,bound,offset,value,Field::field); \
        if (!r.ok()) return r;} while (false)
#define PM_STATE_VALUE(condition,field) \
    do {if (!(condition)) return fail(Reason::ValueMismatch,Field::field);} while (false)
#define PM_STATE_OBSERVE(kind,object,bound,offset,member,field,bit) \
    do {r=readObserved(a,c,i,Object::kind,object,bound,offset,observed.member, \
        Field::field,observed,bit);if (!r.ok()) return r;} while (false)
    Address wlc=0,pub=0,other=0,table=0,main=0,module=0,assoc=0,scan=0,scanPrivate=0;
    uint8_t byte=0;uint64_t power=0;uint32_t number=0;
    PM_STATE_READ(Controller,c,controllerSize,0xa10,wlc,ControllerWlc);
    if (!validPointer(wlc,wlcSize)) return fail(Reason::InvalidPointer,Field::ControllerWlc);
    PM_STATE_READ(Controller,c,controllerSize,0xa18,pub,ControllerPub);
    if (!validPointer(pub,pubSize)) return fail(Reason::InvalidPointer,Field::ControllerPub);
    PM_STATE_READ(Controller,c,controllerSize,0x1aa0,byte,ControllerPowerSleep);
    PM_STATE_VALUE(byte==0,ControllerPowerSleep);
    PM_STATE_READ(Controller,c,controllerSize,0x249a,byte,ControllerPowerCycle);
    PM_STATE_VALUE(byte==0,ControllerPowerCycle);
    PM_STATE_READ(Controller,c,controllerSize,0x1a90,power,ControllerPowerState);
    PM_STATE_VALUE(power==2,ControllerPowerState);
    PM_STATE_READ(Wlc,wlc,wlcSize,0,other,WlcPub);PM_STATE_VALUE(other==pub,WlcPub);
    PM_STATE_READ(Pub,pub,pubSize,0,other,PubOwner);PM_STATE_VALUE(other==wlc,PubOwner);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x338,table,WlcTable);
    if (!validPointer(table,tableSize)) return fail(Reason::InvalidPointer,Field::WlcTable);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x340,main,WlcMain);
    if (!validPointer(main,mainPrefix)) return fail(Reason::InvalidPointer,Field::WlcMain);
    Address returnedMain=0;
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    if (!a.mainGetter(a.context,c,&returnedMain)) return fail(Reason::GetterFailed,Field::MainGetter);
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    PM_STATE_VALUE(returnedMain==main,MainGetter);
    PM_STATE_READ(BssTable,table,tableSize,0,other,TableMain);PM_STATE_VALUE(other==main,TableMain);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x160,module,WlcBssModule);
    if (!validPointer(module,modulePrefix)) return fail(Reason::InvalidPointer,Field::WlcBssModule);
    PM_STATE_READ(BssModule,module,modulePrefix,0,other,BssModuleOwner);
    PM_STATE_VALUE(other==wlc,BssModuleOwner);
    PM_STATE_READ(BssModule,module,modulePrefix,8,number,BssModuleSize);
    PM_STATE_VALUE(number>=mainPrefix,BssModuleSize); // Never expands the read extent.
    PM_STATE_READ(Wlc,wlc,wlcSize,0x1e0,scan,WlcScan);
    if (!validPointer(scan,scanPubSize)) return fail(Reason::InvalidPointer,Field::WlcScan);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x5e8,other,WlcAssocQueue);
    PM_STATE_VALUE(other==0,WlcAssocQueue);
    bool busy=true;
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    if (!a.assocInProgress(a.context,wlc,&busy)) return fail(Reason::GetterFailed,Field::AssocHelper);
    r=prerequisites(a,c,i);if (!r.ok()) return r;
    PM_STATE_VALUE(!busy,AssocHelper);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x28e,byte,WlcGoingDown);PM_STATE_VALUE(byte==0,WlcGoingDown);
    PM_STATE_READ(Wlc,wlc,wlcSize,0x31,byte,WlcClock);PM_STATE_VALUE(byte==1,WlcClock);
    PM_STATE_READ(Pub,pub,pubSize,0x20,byte,PubUp);PM_STATE_VALUE(byte==1,PubUp);
    PM_STATE_READ(Pub,pub,pubSize,0x21,byte,PubHardwareOff);PM_STATE_VALUE(byte==0,PubHardwareOff);
    PM_STATE_READ(Pub,pub,pubSize,0x30,byte,PubHardwareUp);PM_STATE_VALUE(byte==1,PubHardwareUp);
    PM_STATE_READ(MainCfg,main,mainPrefix,0,other,MainOwner);PM_STATE_VALUE(other==wlc,MainOwner);
    // All six fields belong to the already checked main owner and fixed
    // prefix. Observe them before scalar validation so an early mismatch does
    // not hide later role values. Read/authority failure still stops at once.
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,8,mainUp,MainUp,MainUpObserved);
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,9,mainEnable,MainEnable,MainEnableObserved);
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,0xa,mainAP,MainAP,MainAPObserved);
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,0xc,mainAssociated,MainAssociated,MainAssociatedObserved);
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,0x18,mainInfra,MainInfra,MainInfraObserved);
    PM_STATE_OBSERVE(MainCfg,main,mainPrefix,0x60,mainIndex,MainIndex,MainIndexObserved);
    // Finish read-only observation through the original owner-derived chains
    // before applying scalar admission. A structural/read/authority failure
    // still stops immediately; a readable scalar never grants write access.
    PM_STATE_READ(MainCfg,main,mainPrefix,0x128,assoc,MainAssoc);
    if (!validPointer(assoc,assocSize)) return fail(Reason::InvalidPointer,Field::MainAssoc);
    PM_STATE_OBSERVE(Assoc,assoc,assocSize,0xc,assocState,AssocState,AssocStateObserved);
    PM_STATE_READ(ScanPub,scan,scanPubSize,0,scanPrivate,ScanPrivate);
    if (!validPointer(scanPrivate,scanPrivateSize)) return fail(Reason::InvalidPointer,Field::ScanPrivate);
    PM_STATE_READ(ScanPrivate,scanPrivate,scanPrivateSize,0,other,ScanPubBacklink);
    PM_STATE_VALUE(other==scan,ScanPubBacklink);
    PM_STATE_READ(ScanPrivate,scanPrivate,scanPrivateSize,0x10,other,ScanOwner);
    PM_STATE_VALUE(other==wlc,ScanOwner);
    PM_STATE_OBSERVE(ScanPub,scan,scanPubSize,0xa,scanInProgress,ScanInProgress,ScanInProgressObserved);
    PM_STATE_VALUE(observed.mainUp==0,MainUp);
    // Old setAUTH@0x4322c precedes setSSID@0x434ff -> WLC_SET_SSID(26)
    // -> join_start_prep@0xd9281 -> enable@0x176c3d. The pinned
    // cur_etheraddr validation/set_mac path does not inspect main+9. Both
    // canonical boolean states are legal before joining and address setters;
    // enable alone is not idle proof. All other busy/role guards still apply.
    PM_STATE_VALUE(observed.mainEnable<=1,MainEnable);
    PM_STATE_VALUE(observed.mainAP==0,MainAP);
    PM_STATE_VALUE(observed.mainAssociated==0,MainAssociated);
    if (observed.mainInfra!=1) {
        PM_STATE_VALUE(observed.mainInfra==0 && a.infrastructureJoin,MainInfra);
        r=prerequisites(a,c,i);if (!r.ok()) return r;
        const bool infrastructure=a.infrastructureJoin(a.context,c,i);
        r=prerequisites(a,c,i);if (!r.ok()) return r;
        PM_STATE_VALUE(infrastructure,MainInfra);
    }
    PM_STATE_VALUE(observed.mainIndex==0,MainIndex);
    PM_STATE_VALUE(observed.assocState==0,AssocState);
    PM_STATE_VALUE(observed.scanInProgress==0,ScanInProgress);
#undef PM_STATE_VALUE
#undef PM_STATE_READ
#undef PM_STATE_OBSERVE
    // No private address escapes this synchronous call. Every binding remains
    // responsible for the same original lease until its caller finishes apply.
    return prerequisites(a,c,i);
}
}} // namespace PrivateMAC::StateGate
#endif
