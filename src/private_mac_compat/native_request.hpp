// Pinned 25G241 native station-address extension. Does not set any address.
#ifndef SKYWALK_PRIVATE_MAC_NATIVE_REQUEST_HPP
#define SKYWALK_PRIVATE_MAC_NATIVE_REQUEST_HPP
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/errno.h>

namespace PrivateMAC {
constexpr uint32_t SelectedAuthSAE=0x1000;
inline bool supportedStationAuthUpper(uint32_t upper) {
    return upper==0 || upper==8
#if defined(AIRPORT_BRCM_SAE_COMPAT)
        || upper==SelectedAuthSAE
#endif
        ;
}
struct NativeRequest {
    bool requested=false;
    uint8_t address[6] {};
    bool deviceTypeInDhcpAllowed=false;
    // Recognized native scope is retained only in this synchronous owned plan.
    // The old stack cannot apply/query network grouping; require a verified
    // disconnected join before retaining its default link-event behavior.
    bool colocatedScopeUnsupported=false;
    uint8_t colocatedScopeLength=0;
    uint8_t colocatedScope[37] {};
    ~NativeRequest() { memset(static_cast<void *>(this),0,sizeof(*this)); }
};
struct NativeResult { int error; uint32_t field; };
inline bool nativeOverlaps(const void *a,size_t an,const void *b,size_t bn) {
    const uintptr_t x=reinterpret_cast<uintptr_t>(a),y=reinterpret_cast<uintptr_t>(b);
    return x<=y?y-x<an:x-y<bn;
}
inline NativeResult parseNative(const uint8_t *payload,size_t length,NativeRequest &out) {
    // An aliased output must never write the const input (even on error).
    if (payload && nativeOverlaps(payload,length,&out,sizeof(out))) return {EINVAL,0};
    // Ordinary failures cannot leave a previous request/address looking valid.
    out=NativeRequest{};
    if (!payload || length!=908) return {EINVAL,0};
    const bool requested=(payload[468]&0x08U)!=0;
    // Pinned native bit469.40 permits device type in DHCP. It is separate
    // policy carried by the owned plan, not a MAC validity indicator.
    if (payload[469]&~0x40U) return {EOPNOTSUPP,469};
    for (size_t j=470;j<472;j++) if (payload[j]) return {EOPNOTSUPP,static_cast<uint32_t>(j)};
    const bool deviceTypeInDhcpAllowed=(payload[469]&0x40U)!=0;
    if (!requested) {
        if (deviceTypeInDhcpAllowed) return {EOPNOTSUPP,469};
        for (size_t j=512;j<518;j++) if (payload[j]) return {EOPNOTSUPP,static_cast<uint32_t>(j)};
        return {0,0};
    }
    // Apple80211Associate2 only flags a nonzero locally administered unicast.
    // No address generation, permanent-address substitution or flag stripping.
    if ((payload[512]&3U)!=2U) return {EINVAL,512};
    out.requested=true;memcpy(out.address,payload+512,6);
    out.deviceTypeInDhcpAllowed=deviceTypeInDhcpAllowed;
    return {0,0};
}
} // namespace PrivateMAC
#endif
