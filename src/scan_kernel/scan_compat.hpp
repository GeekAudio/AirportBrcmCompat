// Shared by the kernel plugin and offline contract tests.
// Exact Test001 ABI: native 25G241 result / Ventura Legacy result.
#ifndef SKYWALK_SCAN_COMPAT_HPP
#define SKYWALK_SCAN_COMPAT_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>

namespace ScanCompat {
constexpr size_t OldSize = 0x48c, NativeSize = 0x8e0;
constexpr size_t IEOffset = 0x8c, OldIECapacity = 0x400, NativeIECapacity = 0x800;
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
    if (!native || !old || nativeSize != NativeSize || oldSize != OldSize) return EINVAL;
    const auto capacity=read16(native+0x8a), actual=read16(old+0x8a);
    if (read32(native)!=1 || capacity>NativeIECapacity) return EINVAL;
    if (read32(old)!=1 || old[0x22]>15 || old[0x60]>32 || actual>OldIECapacity) return EOVERFLOW;
    const uint16_t copied=actual<capacity ? actual : capacity;
    memcpy(native,old,35);
    memcpy(native+36,old+36,93);
    memcpy(native+132,old+132,5);
    write16(native+0x8a,copied);
    memset(native+IEOffset,0,NativeIECapacity);
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
};
struct Buffer {
    API &api; uint8_t *bytes;
    explicit Buffer(API &a): api(a), bytes(static_cast<uint8_t *>(a.allocate(NativeSize))) {}
    ~Buffer() { if (bytes) { memset(bytes,0,NativeSize); api.deallocate(bytes,NativeSize); } }
    Buffer(const Buffer &)=delete;
    Buffer &operator=(const Buffer &)=delete;
};

// Runs in the original handler's context/gate. It never sleeps, queues work,
// changes scan state or saves a manager-owned result pointer across calls.
inline int handle(API &api,void *controller,void *interface,void *virtualInterface,
                  void *infra,Request *request,bool user64) {
    if (!request || request->type!=11 || request->length!=NativeSize || (!interface && !infra))
        return api.original(controller,interface,virtualInterface,infra,request,user64);
    if (!controller || !request->userData) return EINVAL;
    Buffer native(api);
    if (!native.bytes) return ENOMEM;
    int error=api.copyIn(controller,request->userData,native.bytes,NativeSize);
    if (error) return error;
    if (read32(native.bytes)!=1 || read16(native.bytes+0x8a)>NativeIECapacity) return EINVAL;
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
    error=convert(native.bytes,NativeSize,snapshot,OldSize);
    memset(snapshot,0,OldSize);
    if (error) return error;
    return api.copyOut(controller,native.bytes,request->userData,NativeSize);
}

// Native 25G241 only waits for the BSD SCAN_DONE event when raw capability
// bit46 is present. The owned-process A/B verified that event and the native
// semaphore path. Restrict this compatibility advertisement to the native
// capacity21 request on this machine's main interface. Old capacity4/12 and
// AWDL requests retain their original capability semantics.
inline bool nativeCapabilities(const Request *request,void *controller,void *interface,
                               void *virtualInterface,void *infra) {
    static const char primary[16]="en1";
    return request && controller && (interface || infra) && !virtualInterface &&
        request->type==12 && request->value==0 && request->padding==0 &&
        request->length==21 && request->userData &&
        memcmp(request->interfaceName,primary,sizeof(primary))==0;
}
inline int handleCapabilities(API &api,Original original,void *controller,void *interface,
                              void *virtualInterface,void *infra,Request *request,
                              bool user64,bool *changed=nullptr) {
    if (changed) *changed=false;
    const bool eligible=nativeCapabilities(request,controller,interface,virtualInterface,infra);
    const uint64_t address=eligible ? request->userData : 0;
    int error=original(controller,interface,virtualInterface,infra,request,user64);
    if (error || !eligible) return error;
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
