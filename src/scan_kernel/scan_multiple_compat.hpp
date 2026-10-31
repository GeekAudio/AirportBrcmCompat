// Exact native 25G241/25G332 -> pinned Ventura SET86 compatibility.
// Preserve the original handler, PID/gate checks, scan manager and return code.
#ifndef SKYWALK_SCAN_MULTIPLE_COMPAT_HPP
#define SKYWALK_SCAN_MULTIPLE_COMPAT_HPP
#include "scan_compat.hpp"
#include "primary_interface.hpp"

namespace ScanMultipleCompat {
constexpr size_t LegacySize=0x14e0, NativeSize=0x14e8, StorageSize=NativeSize+LegacySize;
constexpr size_t ChannelOffset=0x214, ChannelStride=12, MaxChannels=400;
static_assert(ChannelOffset+ChannelStride*MaxChannels==0x14d4,"Pinned channel table");
struct Result {int error;uint32_t field;};
inline bool overlap(const void *a,size_t an,const void *b,size_t bn) {
    const auto x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    return x<=y ? y-x<an : x-y<bn;
}
inline Result convert(const uint8_t *native,size_t n,uint8_t *old,size_t o) {
    if (!native || !old || n!=NativeSize || o!=LegacySize || overlap(native,n,old,o))
        return {EINVAL,0};
    if (ScanCompat::read32(native)!=1) return {EINVAL,0};
    const uint32_t ssids=ScanCompat::read32(native+8);
    if (ssids>10) return {EINVAL,8};
    if (ScanCompat::read32(native+0x19c)>16) return {EINVAL,0x19c};
    const uint32_t channels=ScanCompat::read32(native+0x210);
    if (channels>MaxChannels) return {EINVAL,0x210};
    for (uint32_t j=0;j<ssids;j++) {
        const uint32_t offset=0x10+j*40;
        if (ScanCompat::read32(native+offset)>32) return {EINVAL,offset};
    }
    // The native eight-byte extension is SCAN_MIN_TIMESTAMP (SInt64), not
    // padding. Legacy has no matching policy field. Only its absent/zero form
    // is losslessly representable; never discard a nonzero timestamp.
    for (size_t j=LegacySize;j<NativeSize;j++)
        if (native[j]) return {EOPNOTSUPP,LegacySize};
    // Producer/ScanManager/BrcmNIC evidence pins the complete common prefix:
    // SSID/BSSID tables, all 400 channel entries, padding and 64-bit flags.
    memcpy(old,native,LegacySize);
    return {0,0};
}
struct Scope {
    uintptr_t thread=0,caller=0;
    void *controller=nullptr;
    uint64_t source=0;
    const uint8_t *legacy=nullptr;
    bool consumed=false;
    Scope *next=nullptr;
};
struct Lock {void *value=nullptr;void (*enter)(void *)=nullptr;void (*leave)(void *)=nullptr;};
struct Registry {
    Lock lock {};
    Scope *head=nullptr;
    unsigned publication=0;
    bool ready() const {return __atomic_load_n(&publication,__ATOMIC_ACQUIRE)==2;}
    bool prepare(Lock input) {
        if (!input.value || !input.enter || !input.leave) return false;
        unsigned expected=0;
        if (!__atomic_compare_exchange_n(&publication,&expected,1,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return false;
        lock=input;
        __atomic_store_n(&publication,2U,__ATOMIC_RELEASE);
        return true;
    }
    bool add(Scope &s) {
        if (!ready() || !s.thread || !s.caller || !s.controller || !s.source || !s.legacy) return false;
        lock.enter(lock.value);
        for (auto *p=head;p;p=p->next) if (p->thread==s.thread) {
            lock.leave(lock.value);return false;
        }
        s.consumed=false;s.next=head;head=&s;
        lock.leave(lock.value);return true;
    }
    void remove(Scope &s) {
        lock.enter(lock.value);
        for (auto **p=&head;*p;p=&(*p)->next) if (*p==&s) {*p=s.next;break;}
        s.next=nullptr;
        lock.leave(lock.value);
    }
    // -1 means unrelated: use original copyIn. For a matching owner/callsite,
    // wrong controller/source/size, reuse or overlap fails without fallback.
    int consume(uintptr_t thread,uintptr_t caller,void *controller,uint64_t source,
                void *destination,size_t size) {
        if (!ready()) return -1;
        lock.enter(lock.value);
        for (auto *p=head;p;p=p->next) if (p->thread==thread && p->caller==caller) {
            int error=EINVAL;
            if (!p->consumed && p->controller==controller && p->source==source &&
                size==LegacySize && destination && !overlap(destination,size,p->legacy,LegacySize)) {
                memcpy(destination,p->legacy,LegacySize);p->consumed=true;error=0;
            }
            lock.leave(lock.value);return error;
        }
        lock.leave(lock.value);return -1;
    }
};
struct API {
    ScanCompat::Original original=nullptr;
    int (*copyIn)(void *,uint64_t,void *,size_t)=nullptr;
    void *(*allocate)(size_t)=nullptr;
    void (*deallocate)(void *,size_t)=nullptr;
    uintptr_t (*currentThread)()=nullptr;
    Registry *registry=nullptr;
    uintptr_t caller=0;
    bool (*primaryInterface)(void *,void *,const char requestName[16])=nullptr;
};
inline bool eligible(const ScanCompat::Request *r,void *c,void *i,void *v,void *infra,bool user64) {
    PrimaryInterface::Name parsed;
    return r && c && i && !v && !infra && user64 && r->type==86 && r->value==0 &&
        r->length==NativeSize && r->padding==0 && r->userData &&
        PrimaryInterface::parseRequestName(r->interfaceName,parsed);
}
struct Buffer {
    API &api;uint8_t *bytes;
    explicit Buffer(API &a):api(a),bytes(static_cast<uint8_t *>(a.allocate(StorageSize))) {}
    ~Buffer() {if (bytes) {memset(bytes,0,StorageSize);api.deallocate(bytes,StorageSize);}}
    Buffer(const Buffer &)=delete;Buffer &operator=(const Buffer &)=delete;
};
struct RequestLength {
    ScanCompat::Request &request;uint32_t saved;
    explicit RequestLength(ScanCompat::Request &r):request(r),saved(r.length) {r.length=LegacySize;}
    ~RequestLength() {request.length=saved;}
    RequestLength(const RequestLength &)=delete;RequestLength &operator=(const RequestLength &)=delete;
};
inline int handle(API &api,void *c,void *i,void *v,void *infra,ScanCompat::Request *r,bool user64,
                  Result *validation=nullptr,bool *consumed=nullptr) {
    if (validation) *validation={-1,0};
    if (consumed) *consumed=false;
    if (!eligible(r,c,i,v,infra,user64) || !api.primaryInterface ||
        !api.primaryInterface(c,i,r->interfaceName)) return api.original(c,i,v,infra,r,user64);
    Buffer buffer(api);
    if (!buffer.bytes) return ENOMEM;
    int error=api.copyIn(c,r->userData,buffer.bytes,NativeSize);
    if (error) return error;
    const Result result=convert(buffer.bytes,NativeSize,buffer.bytes+NativeSize,LegacySize);
    if (validation) *validation=result;
    if (result.error) return result.error;
    if (!api.primaryInterface(c,i,r->interfaceName)) return api.original(c,i,v,infra,r,user64);
    Scope scope;
    scope.thread=api.currentThread();scope.caller=api.caller;scope.controller=c;
    scope.source=r->userData;scope.legacy=buffer.bytes+NativeSize;
    if (!api.registry->add(scope)) return EBUSY;
    {
        // Keep the real userspace address and original request allocation.
        // Only the pinned synchronous copyIn call receives our owned prefix.
        RequestLength length(*r);
        error=api.original(c,i,v,infra,r,user64);
    }
    api.registry->remove(scope);
    if (consumed) *consumed=scope.consumed;
    if (!error && !scope.consumed) return EIO;
    return error;
}
}
#endif
