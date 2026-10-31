// Shared by the kernel plugin and offline contract tests.
// Independently inspected native result shapes and the fixed Ventura result.
#ifndef SKYWALK_SCAN_COMPAT_HPP
#define SKYWALK_SCAN_COMPAT_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>
#include "primary_interface.hpp"

namespace ScanCompat {
constexpr size_t OldSize = 0x48c, NativeSize = 0x8e0;
constexpr size_t IEOffset = 0x8c, OldIECapacity = 0x400, NativeIECapacity = 0x800;
// The compact native producer (23J631) appends a 64-byte scan identifier to
// the 1024-byte IE result. The extended producer has a 2048-byte IE array.
// Length selects a known request schema; it is not an OS-version heuristic.
constexpr size_t CompactNativeSize = 0x4cc;
constexpr size_t WideNativeSize = 0x8d8; // 24H232: 2048-byte IEs, shorter native tail.
inline size_t resultIECapacity(size_t size) {
    return size==CompactNativeSize?OldIECapacity:
        ((size==WideNativeSize || size==NativeSize)?NativeIECapacity:0);
}
// The old dispatcher appends pointer-width metadata after this 40-byte prefix.
// Wrappers only access the prefix; the original request is never reallocated.
struct Request {
    char interfaceName[16];
    int32_t type, value;
    uint32_t length, padding;
    uint64_t userData;
};
static_assert(sizeof(Request) == 40, "Audited common x86_64 request prefix; never copied as a whole");
static_assert(offsetof(Request, length) == 24 && offsetof(Request, userData) == 32,
              "Audited request offsets");
inline uint16_t read16(const void *p) { uint16_t x; memcpy(&x,p,sizeof(x)); return x; }
inline uint32_t read32(const void *p) { uint32_t x; memcpy(&x,p,sizeof(x)); return x; }
inline void write16(void *p,uint16_t x) { memcpy(p,&x,sizeof(x)); }

// On error the native buffer is unchanged. Native-only tail and input padding
// are preserved. No uninitialized Legacy padding is copied to userspace.
inline int convert(uint8_t *native, size_t nativeSize, const uint8_t *old, size_t oldSize) {
    const size_t limit=resultIECapacity(nativeSize);
    if (!native || !old || !limit || oldSize != OldSize) return EINVAL;
    const auto capacity=read16(native+0x8a), actual=read16(old+0x8a);
    if (read32(native)!=1 || capacity>limit) return EINVAL;
    if (read32(old)!=1 || old[0x22]>15 || old[0x60]>32 || actual>OldIECapacity) return EOVERFLOW;
    const uint16_t copied=actual<capacity ? actual : capacity;
    memcpy(native,old,35);
    memcpy(native+36,old+36,93);
    memcpy(native+132,old+132,5);
    write16(native+0x8a,copied);
    memset(native+IEOffset,0,limit);
    memcpy(native+IEOffset,old+IEOffset,copied);
    return 0;
}

// The final bool means a 64-bit user request, not a kernel address-space caller.
using Original = int (*)(void *,void *,void *,void *,Request *,bool);
struct API {
    Original original;
    void *(*allocate)(size_t);
    void (*deallocate)(void *,size_t);
    int (*copyIn)(void *,uint64_t,void *,size_t);
    int (*copyOut)(void *,const void *,uint64_t,size_t);
    void *(*manager)(void *);
    int (*getResult)(void *,const uint8_t **);
    bool (*primaryInterface)(void *,void *,const char requestName[16])=nullptr;
};
struct Buffer {
    API &api; size_t size; uint8_t *bytes;
    explicit Buffer(API &a,size_t n=NativeSize): api(a),size(n),bytes(static_cast<uint8_t *>(a.allocate(n))) {}
    ~Buffer() { if (bytes) { memset(bytes,0,size); api.deallocate(bytes,size); } }
    Buffer(const Buffer &)=delete;
    Buffer &operator=(const Buffer &)=delete;
};

// Runs in the original handler's context/gate. It never sleeps, queues work,
// changes scan state or saves a manager-owned result pointer across calls.
inline int handle(API &api,void *controller,void *interface,void *virtualInterface,
                  void *infra,Request *request,bool user64) {
    PrimaryInterface::Name parsedName;
    const bool nativeScan=request && request->type==11 && resultIECapacity(request->length);
    if (nativeScan && (virtualInterface || (!interface && infra)))
        return api.original(controller,interface,virtualInterface,infra,request,user64);
    if (nativeScan && controller && interface && (!api.primaryInterface ||
        !PrimaryInterface::parseRequestName(request->interfaceName,parsedName) ||
        !api.primaryInterface(controller,interface,request->interfaceName)))
        return api.original(controller,interface,virtualInterface,infra,request,user64);
    if (!nativeScan || (!interface && !infra))
        return api.original(controller,interface,virtualInterface,infra,request,user64);
    if (!controller || !request->userData) return EINVAL;
    const size_t nativeSize=request->length;
    Buffer native(api,nativeSize);
    if (!native.bytes) return ENOMEM;
    int error=api.copyIn(controller,request->userData,native.bytes,nativeSize);
    if (error) return error;
    if (read32(native.bytes)!=1 || read16(native.bytes+0x8a)>resultIECapacity(nativeSize)) return EINVAL;
    void *manager=api.manager(controller);
    if (!manager) return ENXIO;
    const uint8_t *result=nullptr;
    error=api.getResult(manager,&result);
    if (error) return error; // Preserve EBUSY, per-PID EOF and all driver errors.
    if (!result) return EIO;
    // Copy immediately before any potentially blocking copyOut. Original code
    // copies the same exact 1164 bytes from this manager-owned object.
    uint8_t snapshot[OldSize];
    memcpy(snapshot,result,OldSize);
    error=convert(native.bytes,nativeSize,snapshot,OldSize);
    memset(snapshot,0,OldSize);
    if (error) return error;
    if (!api.primaryInterface || !api.primaryInterface(controller,interface,request->interfaceName))
        return ENXIO;
    return api.copyOut(controller,native.bytes,request->userData,nativeSize);
}

// The native 23J631, 24H232 and 25G241 producers gate SCAN_DONE waiting on
// raw capability bit46. Their capacity16/19/21 requests share the same capability
// prefix. The event path has an owned-process A/B baseline on 25G241. Only an
// identity-matched primary interface may advertise it; capacity4/12 and AWDL
// keep their original semantics.
inline bool nativeCapabilities(const Request *request,void *controller,void *interface,
                               void *virtualInterface,void *infra) {
    PrimaryInterface::Name parsed;
    return request && controller && (interface || infra) && !virtualInterface &&
        request->type==12 && request->value==0 && request->padding==0 &&
        (request->length==16 || request->length==19 || request->length==21) && request->userData &&
        PrimaryInterface::parseRequestName(request->interfaceName,parsed);
}
inline int handleCapabilities(API &api,Original original,void *controller,void *interface,
                              void *virtualInterface,void *infra,Request *request,
                              bool user64,bool *changed=nullptr) {
    if (changed) *changed=false;
    const bool eligible=nativeCapabilities(request,controller,interface,virtualInterface,infra) &&
        interface && api.primaryInterface && api.primaryInterface(controller,interface,request->interfaceName);
    const uint64_t address=eligible ? request->userData : 0;
    int error=original(controller,interface,virtualInterface,infra,request,user64);
    if (error || !eligible) return error;
    if (!api.primaryInterface || !api.primaryInterface(controller,interface,request->interfaceName)) return 0;
    // The pinned Legacy handler strips the version and returns min(cap,12).
    // Unexpected replies pass through without advertising an unverified ABI.
    if (request->length!=12 || request->userData!=address) return 0;
    struct RawCapabilities {
        uint8_t bytes[12] {};
        ~RawCapabilities() { memset(bytes,0,sizeof(bytes)); }
    } raw;
    error=api.copyIn(controller,address,raw.bytes,sizeof(raw.bytes));
    if (error) return error;
    if (raw.bytes[5]&0x40) return 0;
    raw.bytes[5]|=0x40;
    error=api.copyOut(controller,raw.bytes,address,sizeof(raw.bytes));
    if (!error && changed) *changed=true;
    return error;
}
} // namespace ScanCompat
#endif
