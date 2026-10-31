// Pinned 25G241 -> Legacy SET20 adapter. Never writes a user SET buffer.
#ifndef SKYWALK_ASSOCIATION_COMPAT_HPP
#define SKYWALK_ASSOCIATION_COMPAT_HPP
#include "scan_compat.hpp"
#include "association_survey.hpp"
#include "../private_mac_compat/native_request.hpp"

namespace AssociationCompat {
constexpr size_t NativeSize=908, LegacySize=548, StorageSize=NativeSize+LegacySize;
struct Result { int error; uint32_t field; };
inline Result refused(uint32_t field,int error=EOPNOTSUPP) { return {error,field}; }
inline bool overlap(const void *a,size_t an,const void *b,size_t bn) {
    const auto x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    return x<=y ? y-x<an : x-y<bn;
}
// Only infrastructure profiles with proven common fields. The explicit SAE
// candidate preserves selected0x1000 and its password carrier; never alias8.
// No implicit WPA downgrade, private-MAC suppression or unknown tail loss.
// Known colocated-scope grouping is an explicit disconnected-only fallback.
inline Result convert(const uint8_t *native,size_t n,uint8_t *old,size_t o,
                      PrivateMAC::NativeRequest *privatePlan=nullptr) {
    using ScanCompat::read16; using ScanCompat::read32;
    if (privatePlan && ((native && overlap(native,n,privatePlan,sizeof(*privatePlan))) ||
                        (old && overlap(old,o,privatePlan,sizeof(*privatePlan))))) return refused(0,EINVAL);
    if (privatePlan) *privatePlan=PrivateMAC::NativeRequest{};
    if (!native || !old || n!=NativeSize || o!=LegacySize || overlap(native,n,old,o))
        return refused(0,EINVAL);
    if (read32(native)!=1) return refused(0,EINVAL);
    if (read16(native+4)!=2) return refused(4);
    if (read16(native+6)!=0) return refused(6,EINVAL);
    if (read32(native+8)!=1) return refused(8);
    const uint32_t upper=read32(native+12);
    if (!PrivateMAC::supportedStationAuthUpper(upper)) return refused(12);
    const uint32_t ssid=read32(native+16);
    if (!ssid || ssid>32) return refused(16,EINVAL);
    if (read32(native+60)>1) return refused(60,EINVAL);
    const uint32_t key=read32(native+64),cipher=read32(native+68),pmk=read32(native+472);
    if (key>64) return refused(64,EINVAL);
    if (pmk>32) return refused(472,EINVAL);
    if (!upper) {
        if (cipher || key || pmk) return refused(68);
        // An explicit security carrier must never silently become open.
        // Preserve only the nested carrier version; all key/RSN/PMK bytes
        // have to be empty for a profile which explicitly requests no WPA.
        for (size_t j=64;j<467;j++) if (native[j]) return refused(static_cast<uint32_t>(j));
        for (size_t j=472;j<508;j++) if (native[j]) return refused(static_cast<uint32_t>(j));
    } else if (upper==PrivateMAC::SelectedAuthSAE) {
        // Narrow saved-producer schema: PWD8..63 and the derived PMK32
        // extension. Legacy receives the full password carrier unchanged and
        // programs its own SAE passphrase manager. Raw PSKs,64-byte keys and
        // PMK0 have no admitted SAE producer schema in this first candidate.
        if (cipher!=10 || key<8 || key>63 || pmk!=32) return refused(68);
    } else if (!((cipher==6 && key==32 && (pmk==0 || pmk==32)) ||
                 (cipher==10 && key>=1 && key<=64 && pmk==32))) return refused(68);
    if (read32(native+140)>8) return refused(140,EINVAL);
    if (read32(native+160)>16) return refused(160,EINVAL);
    if (read32(native+180)>16) return refused(180,EINVAL);
    if (read16(native+208)>257) return refused(208,EINVAL);
    // A real private consumer must keep this owned plan in its ioctl scope and
    // apply it at the audited driver-auth site before allowing association.
    if ((native[468]&0x08) && !privatePlan) return refused(468);
    PrivateMAC::NativeRequest plan;
    const auto parsed=PrivateMAC::parseNative(native,n,plan);
    if (parsed.error) return refused(parsed.field,parsed.error);
    const uint32_t allowed=read32(native+508);
    // AuthUpper is a selected authentication enum; AllowedAuth is a separate
    // restriction-policy mask. Both pinned native and reference WPA2-PSK
    // producers use 4 / 0x40000004 for selected upper=8. The legacy driver
    // consumes the original mask at504; neither 0, 4 nor8 are aliases.
    // Preserve the exact known mask, including its high capability bit.
    if ((!upper && allowed) ||
        ((upper==8 || upper==PrivateMAC::SelectedAuthSAE) &&
         allowed!=0 && allowed!=4 && allowed!=0x40000004U)) return refused(508);
    const bool hasScope=(native[468]&0x40U)!=0;
    if (hasScope) {
        // A scope controls native network-group event suppression. It has no
        // lossless old548 representation or supported old GET387. Ordinary
        // disconnected joins may use legacy default events, never roaming.
        // A real private consumer must enforce this before originalAssociate.
        if (!plan.requested) return refused(468);
        const uint32_t length=read32(native+580);
        if (!length || length>36) return refused(580,EINVAL);
        for (size_t j=0;j<length;j++)
            if (native[584+j]<0x21 || native[584+j]>0x7e) return refused(584,EINVAL);
        for (size_t j=length;j<40;j++) if (native[584+j]) return refused(584,EINVAL);
        plan.colocatedScopeUnsupported=true;
        plan.colocatedScopeLength=static_cast<uint8_t>(length);
        memcpy(plan.colocatedScope,native+584,length);
    }
    for (size_t i=512;i<NativeSize;i++) {
        if (plan.requested && i<518) continue; // Out-of-band station MAC plan.
        if (hasScope && i>=580 && i<624) continue; // Validated owned unsupported hint.
        if (i==899) { // ASSOC_6G_ENABLE: unspecified(2) or explicitly off(1).
            if (native[i]!=1 && native[i]!=2) return refused(899);
        } else if (native[i]) return refused(static_cast<uint32_t>(i));
    }
    memset(old,0,LegacySize);
    memcpy(old,native,6);
    ScanCompat::write16(old+6,1);
    ScanCompat::write16(old+8,static_cast<uint16_t>(upper));
    memcpy(old+12,native+16,496); // Bounded SSID/key/RSN/flags/PSKPMK/allow-auth.
    if (plan.requested) {
        old[464]&=static_cast<uint8_t>(~0x08U);
        old[465]&=static_cast<uint8_t>(~0x40U);
        if (plan.colocatedScopeUnsupported) old[464]&=static_cast<uint8_t>(~0x40U);
    }
    // Private address and DHCP device-type policy are carried by the owned
    // plan, not unknown legacy flag bits. The caller requires actual MAC work.
    // Returning a plan is NOT proof that it has been consumed/applied.
    if (privatePlan) *privatePlan=plan;
    return {0,0};
}

struct Scope {
    uintptr_t thread=0,caller=0;
    void *controller=nullptr,*interface=nullptr;
    uint64_t source=0;
    const uint8_t *legacy=nullptr;
    bool consumed=false;
    PrivateMAC::NativeRequest privatePlan {};
    uint32_t authUpper=0;
    void *privateFrame=nullptr;
    bool driverValidated=false;
    bool privateApplied=false,privateCompleted=false;
    int privateError=EOPNOTSUPP;
    Scope *next=nullptr;
    Scope()=default;
    Scope(const Scope &)=delete;
    Scope &operator=(const Scope &)=delete;
};
// Acquired only by the real driver wrapper AFTER its pinned caller and full
// 548-byte comparison. Never use the mere presence of a registry Scope as
// proof that the actual original driver entry has been validated.
struct DriverValidationLease {
    Scope *scope=nullptr;
    explicit DriverValidationLease(Scope &s) {
        if (!s.driverValidated && s.consumed && s.privatePlan.requested && s.legacy && s.source) {
            s.driverValidated=true;scope=&s;
        }
    }
    ~DriverValidationLease() {if (scope) scope->driverValidated=false;}
    bool acquired() const {return scope!=nullptr;}
    DriverValidationLease(const DriverValidationLease &)=delete;
    DriverValidationLease &operator=(const DriverValidationLease &)=delete;
};
inline bool infrastructureIntent(const Scope &s,uintptr_t owner,void *controller,void *interface) {
    if (!owner || !controller || !interface || !s.driverValidated || !s.consumed ||
        s.thread!=owner || s.controller!=controller || s.interface!=interface ||
        !s.caller || !s.source || !s.legacy || !s.privatePlan.requested ||
        !PrivateMAC::supportedStationAuthUpper(s.authUpper)) return false;
    // This is the immutable owned conversion, not the driver's mutable copy.
    // Original setAP_MODE applies mode2 only AFTER the auth hook.
    return ScanCompat::read32(s.legacy)==1 && ScanCompat::read16(s.legacy+4)==2 &&
        ScanCompat::read16(s.legacy+6)==1 && ScanCompat::read16(s.legacy+8)==s.authUpper;
}
struct Lock { void *value; void (*enter)(void *); void (*leave)(void *); };
struct Registry {
    Lock lock {};
    Scope *head=nullptr;
    bool add(Scope &scope) {
        if (!scope.thread || !scope.caller || !scope.controller || !scope.source || !scope.legacy ||
            !lock.value || !lock.enter || !lock.leave) return false;
        lock.enter(lock.value);
        for (auto *p=head;p;p=p->next) if (p->thread==scope.thread) {
            lock.leave(lock.value);return false;
        }
        scope.consumed=false;scope.next=head;head=&scope;
        lock.leave(lock.value);return true;
    }
    void remove(Scope &scope) {
        lock.enter(lock.value);
        for (auto **p=&head;*p;p=&(*p)->next) if (*p==&scope) {
            *p=scope.next;break;
        }
        scope.next=nullptr;
        lock.leave(lock.value);
    }
    // Only the actual current owner thread may use this borrowed pointer, and
    // only during the synchronous original handler on that same stack. No
    // callback/worker is permitted to retain it after remove().
    Scope *find(uintptr_t thread,void *controller,void *interface) {
        if (!thread || !controller || !interface || !lock.value) return nullptr;
        Scope *found=nullptr;
        lock.enter(lock.value);
        for (auto *p=head;p;p=p->next) if (p->thread==thread && p->controller==controller &&
                                         p->interface==interface) {found=p;break;}
        lock.leave(lock.value);return found;
    }
    // -1 means an unrelated call must use original copyIn. A scoped target
    // mismatch or repeated consumption is an error, never raw native fallback.
    int consume(uintptr_t thread,uintptr_t caller,void *controller,uint64_t source,
                void *destination,size_t size) {
        if (!lock.value) return -1;
        lock.enter(lock.value);
        for (auto *p=head;p;p=p->next) if (p->thread==thread && p->caller==caller) {
            int result=EINVAL;
            if (!p->consumed && p->controller==controller && p->source==source &&
                size==LegacySize && destination && !overlap(destination,size,p->legacy,LegacySize)) {
                memcpy(destination,p->legacy,LegacySize);p->consumed=true;result=0;
            }
            lock.leave(lock.value);return result;
        }
        lock.leave(lock.value);return -1;
    }
};
using CopyIn=int (*)(void *,uint64_t,void *,size_t);
struct API {
    ScanCompat::Original original=nullptr;
    CopyIn copyIn=nullptr;
    void *(*allocate)(size_t)=nullptr;
    void (*deallocate)(void *,size_t)=nullptr;
    uintptr_t (*currentThread)()=nullptr;
    Registry *registry=nullptr;
    uintptr_t caller=0;
    int (*entryAllowed)(void *,void *)=nullptr;
    bool (*privateAvailable)(void *,void *)=nullptr;
    void (*observeFlags)(uint32_t,uint8_t)=nullptr;
    void (*observeSurvey)(const AssociationSurvey::Snapshot &)=nullptr;
};
inline bool mainRequest(const ScanCompat::Request *r,void *c,void *i,void *v,void *infra) {
    static const char primary[16]="en1";
    return r && c && i && !v && !infra && r->type==20 &&
        memcmp(r->interfaceName,primary,16)==0;
}
inline bool eligible(const ScanCompat::Request *r,void *c,void *i,void *v,void *infra,bool user64) {
    return mainRequest(r,c,i,v,infra) && user64 && r->value==0 &&
        r->length==NativeSize && r->padding==0 && r->userData;
}
struct Buffer {
    API &api; uint8_t *bytes;
    explicit Buffer(API &a):api(a),bytes(static_cast<uint8_t *>(a.allocate(StorageSize))) {}
    ~Buffer() { if (bytes) { memset(bytes,0,StorageSize);api.deallocate(bytes,StorageSize); } }
    Buffer(const Buffer &)=delete;
    Buffer &operator=(const Buffer &)=delete;
};
inline int handle(API &api,void *c,void *i,void *v,void *infra,ScanCompat::Request *r,bool user64,
                  Result *validation=nullptr,bool *consumed=nullptr) {
    if (validation) *validation={-1,0};
    if (consumed) *consumed=false;
    if (api.entryAllowed && mainRequest(r,c,i,v,infra)) {
        const int admission=api.entryAllowed(c,i);if (admission) return admission;
    }
    if (!eligible(r,c,i,v,infra,user64)) return api.original(c,i,v,infra,r,user64);
    Buffer buffer(api);
    if (!buffer.bytes) return ENOMEM;
    int error=api.copyIn(c,r->userData,buffer.bytes,NativeSize);
    if (error) return error;
    // Only nonidentifying flags from a successfully copied, bounded request.
    // No pointer, MAC, SSID, key or arbitrary buffer contents are exported.
    if (api.observeFlags) api.observeFlags(ScanCompat::read32(buffer.bytes+467)&0xffffffU,buffer.bytes[469]);
    if (api.observeSurvey) {
        AssociationSurvey::Snapshot survey;
        if (AssociationSurvey::inspect(buffer.bytes,NativeSize,survey)==AssociationSurvey::Status::Ok)
            api.observeSurvey(survey);
    }
    PrivateMAC::NativeRequest privatePlan;
    const bool hasConsumer=api.privateAvailable && api.privateAvailable(c,i);
    const Result result=convert(buffer.bytes,NativeSize,buffer.bytes+NativeSize,LegacySize,
                                hasConsumer?&privatePlan:nullptr);
    if (validation) *validation=result;
    if (result.error) return result.error;
    Scope scope;
    scope.thread=api.currentThread();scope.caller=api.caller;scope.controller=c;scope.interface=i;
    scope.source=r->userData;scope.legacy=buffer.bytes+NativeSize;
    scope.privatePlan=privatePlan;scope.authUpper=ScanCompat::read32(buffer.bytes+12);
    if (!api.registry->add(scope)) return EBUSY;
    error=api.original(c,i,v,infra,r,user64);
    api.registry->remove(scope);
    if (consumed) *consumed=scope.consumed;
    // Converting the extension is never sufficient. A registered real backend
    // must have applied and finished the very same scoped request. Preserve
    // original failures, but do not turn missing private work into success.
    if (!error && scope.privatePlan.requested && (!scope.privateApplied ||
        !scope.privateCompleted || scope.privateError)) error=scope.privateError?scope.privateError:EIO;
    memset(scope.privatePlan.address,0,sizeof(scope.privatePlan.address));
    memset(privatePlan.address,0,sizeof(privatePlan.address));
    if (!error && !scope.consumed) return EIO;
    return error;
}
}
#endif
