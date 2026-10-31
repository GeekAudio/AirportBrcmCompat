// Small admission checks for routing the public ioctl boundary. These do not
// decode an ifnet layout or infer the semantics of an unknown private function.
#ifndef PRIVATE_MAC_IFNET_KPI_CONTRACT_HPP
#define PRIVATE_MAC_IFNET_KPI_CONTRACT_HPP
#include <stddef.h>
#include <stdint.h>

namespace PrivateMAC { namespace IfnetKPIContract {
constexpr size_t PrefixBudget=48;
constexpr size_t MaximumRouteBytes=14;

// The patcher's trampoline copies complete entry instructions without fixing
// relative operands. Admit only a bounded prefix of position-independent
// register/stack instructions. This deliberately excludes calls, branches,
// RIP-relative loads, and all memory operands other than push/pop.
// The decoded length is for checking, not for constructing a trampoline.
inline size_t safeRoutePrefix(const uint8_t *p,size_t size) {
    if (!p || size<MaximumRouteBytes) return 0;
    const size_t limit=size<PrefixBudget?size:PrefixBudget;
    size_t offset=0;
    while (offset<MaximumRouteBytes) {
        const size_t left=limit-offset;
        size_t length=0;
        const uint8_t byte=p[offset];
        if (byte==0x90 || (byte>=0x50 && byte<=0x5f)) length=1;
        else if (left>=2 && byte==0x41 && p[offset+1]>=0x50 && p[offset+1]<=0x5f) length=2;
        else if (left>=4 && byte==0xf3 && p[offset+1]==0x0f &&
                 p[offset+2]==0x1e && p[offset+3]==0xfa) length=4; // ENDBR64.
        else if (left>=3 && byte>=0x48 && byte<=0x4f &&
                 (p[offset+1]==0x89 || p[offset+1]==0x8b) &&
                 (p[offset+2]&0xc0)==0xc0) length=3;
        else if (left>=4 && byte==0x48 && p[offset+1]==0x83 &&
                 p[offset+2]==0xec && p[offset+3]>0 && p[offset+3]<0x80) length=4;
        else if (left>=7 && byte==0x48 && p[offset+1]==0x81 && p[offset+2]==0xec &&
                 !(p[offset+6]&0x80)) length=7;
        if (!length || length>left) return 0;
        offset+=length;
    }
    return offset;
}
} }
#endif
