// Portable shape/rendering only. Contains no task, entitlement or IOKit mock.
#ifndef AIRPORT_AWDL_DRIVER_VERSION_FORMAT_HPP
#define AIRPORT_AWDL_DRIVER_VERSION_FORMAT_HPP
#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace AWDLKernel {
constexpr size_t NativeFrameSize=0x3c30;
// Sonoma/Sequoia's IO80211 userland issues the original inline GET43 with a
// 256-byte output buffer. The candidate Tahoe/OOL route is still pinned to
// 384 bytes; these are two audited envelopes, not a general size range.
constexpr size_t LegacyVersionCapacity=256, NativeVersionCapacity=384;
inline bool validVersionCapacity(size_t capacity) {
    return capacity==LegacyVersionCapacity || capacity==NativeVersionCapacity;
}
struct LegacyVersion {
    uint32_t version;
    uint16_t length;
    uint8_t string[256];
};
static_assert(sizeof(LegacyVersion)==264,"Pinned old typed GET43 ABI");
static_assert(offsetof(LegacyVersion,string)==6,"Old string is not a typed output header");
enum class VersionStatus : uint32_t {
    Passed=0, Shape, Unbound, TaskIdentity, Entitlement, ObjectIdentity,
    WorkLoop, BackendError, BackendFormat
};
struct VersionResult {
    VersionStatus status=VersionStatus::Shape;
    int32_t rawBackendStatus=0;
    bool backendCalled=false;
    uint32_t observedVersion=0;
    uint16_t observedLength=0;
    size_t returned=0;
};
struct VersionCall {
    uint32_t selector=0,scalarInputCount=0,scalarOutputCount=0,asyncReferenceCount=0;
    const void *input=nullptr;
    size_t inputSize=0;
    void *output=nullptr;
    size_t outputCapacity=0;
};
inline bool versionRangesOverlap(const void *a,size_t an,const void *b,size_t bn) {
    const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    return x<=y ? y-x<an : x-y<bn;
}
inline bool validVersionCall(const VersionCall &call) {
    if (call.selector || call.scalarInputCount || call.scalarOutputCount ||
        call.asyncReferenceCount || !call.input || !call.output ||
        call.inputSize!=NativeFrameSize || !validVersionCapacity(call.outputCapacity) ||
        reinterpret_cast<uintptr_t>(call.input)>UINTPTR_MAX-call.inputSize ||
        reinterpret_cast<uintptr_t>(call.output)>UINTPTR_MAX-call.outputCapacity ||
        versionRangesOverlap(call.input,call.inputSize,call.output,call.outputCapacity) ||
        versionRangesOverlap(&call,sizeof(call),call.output,call.outputCapacity)) return false;
    const auto *bytes=static_cast<const uint8_t *>(call.input);
    static const uint8_t command[4]={0xc9,0x69,0x28,0xc0};
    static const uint8_t name[16]={'a','w','d','l','0',0};
    if (memcmp(bytes,command,4) || memcmp(bytes+0x3c08,name,16)) return false;
    // The audited 14/15 producers zero all 0x3c30 bytes before writing the
    // command, interface name and GET43 value. There is no payload, footer
    // length or pointer; reject hidden nonzero bytes in this empty frame.
    for (size_t j=4;j<0x3c08;++j) if (bytes[j]) return false;
    for (size_t j=0x3c18;j<NativeFrameSize;++j)
        if (bytes[j]!=(j==0x3c18?43:0)) return false;
    return true;
}
inline VersionResult renderLegacyVersion(const LegacyVersion &source,int32_t raw,
                                          void *output,size_t capacity) {
    VersionResult result;
    result.backendCalled=true;result.rawBackendStatus=raw;
    if (!output || !validVersionCapacity(capacity) ||
        reinterpret_cast<uintptr_t>(output)>UINTPTR_MAX-capacity ||
        versionRangesOverlap(&source,sizeof(source),output,capacity)) return result;
    memset(output,0,capacity);
    if (raw) {result.status=VersionStatus::BackendError;return result;}
    result.observedVersion=source.version;result.observedLength=source.length;
    if (source.version!=1 || source.length>sizeof(source.string) ||
        source.length>capacity) {
        result.status=VersionStatus::BackendFormat;return result;
    }
    // Native GET43 returns only the real string bytes, not old version/length.
    memcpy(output,source.string,source.length);
    result.returned=source.length;result.status=VersionStatus::Passed;
    return result;
}
} // namespace AWDLKernel
#endif
