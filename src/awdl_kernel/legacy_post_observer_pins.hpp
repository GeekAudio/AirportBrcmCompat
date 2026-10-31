// Exact SHA-pinned archive instruction windows, never synthetic driver data.
// Stateless bounded mapped-image parser; it does not discover readable VM or
// establish a loaded-image lifetime. Caller owns that contract until reboot.
#ifndef AIRPORT_AWDL_LEGACY_POST_OBSERVER_PINS_HPP
#define AIRPORT_AWDL_LEGACY_POST_OBSERVER_PINS_HPP
#include <stddef.h>
#include <stdint.h>
#include <string.h>
namespace AWDLKernel {
struct ObserverPins {uintptr_t base=0,entry=0;size_t extent=0;uintptr_t role=0,bsdName=0;};
enum class ObserverPinStatus : uint32_t {Passed=0,Input,MachO,UUID,Text,Guard};
namespace ObserverPinDetail {
inline bool range(size_t at,size_t n,size_t end) {return at<=end && n<=end-at;}
inline uint32_t u32(const uint8_t *p) {uint32_t x;memcpy(&x,p,4);return x;}
inline uint64_t u64(const uint8_t *p) {uint64_t x;memcpy(&x,p,8);return x;}
inline bool name(const uint8_t *p,const char *s) {
    size_t n=0;while (s[n] && n<16) {if (p[n]!=static_cast<uint8_t>(s[n])) return false;++n;}
    if (n==16) return false;for (;n<16;++n) if (p[n]) return false;return true;
}
constexpr uint8_t UUID[16]={0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab};
constexpr uint8_t ObserverEntryGuard[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x81,0xec,0x18,0x01,0x00,0x00};
constexpr uint8_t ObserverSyncGuard[]={0x55,0x48,0x89,0xe5,0x53,0x50,0x83,0xbf,0xc0,0x00,0x00,0x00,0x06,0x75,0x2a,0x48,0x89,0xfb,0xbe,0x2e,0x00,0x00,0x00,0x31,0xd2,0x31,0xc9,0xe8,0xbe,0xe1,0xff,0xff};
constexpr uint8_t ObserverPeerGuard[]={0x31,0xc0,0x48,0x8d,0x55,0x88,0x48,0x89,0x42,0x3c,0x48,0x89,0x42,0x36,0x48,0x89,0x42,0x2e,0x48,0x89,0x42,0x26,0x48,0x89,0x42,0x1e,0x48,0x89,0x42,0x16,0x48,0x89,0x42,0x0e,0x48,0x89,0x42,0x06,0x8b,0x46,0x20,0x89,0x02,0x0f,0xb7,0x46,0x24,0x66,0x89,0x42,0x04,0xc7,0x42,0x08,0x01,0x00,0x00,0x00,0x48,0x8b,0xbf,0xb8,0x00,0x00,0x00,0xb9,0x44,0x00,0x00,0x00,0xbe,0x2f,0x00,0x00,0x00,0xe8,0x68,0xed,0x06,0x00};
constexpr uint8_t ObserverRemoveGuard[]={0x48,0x8d,0x55,0x88,0x4c,0x89,0x6a,0x3c,0x4c,0x89,0x6a,0x36,0x4c,0x89,0x6a,0x2e,0x4c,0x89,0x6a,0x26,0x4c,0x89,0x6a,0x1e,0x4c,0x89,0x6a,0x16,0x4c,0x89,0x6a,0x0e,0x4c,0x89,0x6a,0x06,0x48,0x8b,0x4d,0x80,0x8b,0x01,0x89,0x02,0x0f,0xb7,0x41,0x04,0x66,0x89,0x42,0x04,0xc7,0x42,0x08,0x01,0x00,0x00,0x00,0x49,0x8b,0xbf,0xb8,0x00,0x00,0x00,0xb9,0x44,0x00,0x00,0x00,0xbe,0x2f,0x00,0x00,0x00,0xe8,0x8f,0x53,0x04,0x00};
constexpr uint8_t ObserverRoleGuard[]={0x55,0x48,0x89,0xe5,0x8b,0x87,0xc0,0,0,0,0x5d,0xc3};
constexpr uint8_t ObserverNameGuard[]={0x55,0x48,0x89,0xe5,0x48,0x8d,0x87,0xd8,0,0,0,0x5d,0xc3};
// External E8 operands at3f1ab/3f1d5/3f1f2 are excluded: the real
// loader relocates them. Install resolves and checks their live destinations.
constexpr uint8_t ObserverAFPrefix[]={0x55,0x48,0x89,0xe5,0x41,0x57,0x41,0x56,0x41,0x55,0x41,0x54,0x53,0x48,0x83,0xec,0x28,0x49,0x89,0xcc,0x49,0x89,0xd7,0x48,0x89,0x75,0xb0,0x49,0x89,0xfe};
constexpr uint8_t ObserverAFAllocate[]={0x4c,0x8d,0x6a,0x48,0xc7,0x45,0xcc,0xaa,0xaa,0xaa,0xaa,0x4c,0x89,0xef,0xe8};
constexpr uint8_t ObserverAFHeaderCopy[]={0x48,0x89,0x45,0xb8,0x4c,0x89,0x6d,0xc0,0xc7,0x45,0xc8,0x01,0x00,0x00,0x00,0x48,0x85,0xc0,0x74,0x4c,0x48,0x89,0xc3,0xba,0x48,0x00,0x00,0x00,0x48,0x89,0xc7,0x4c,0x89,0xe6,0x4c,0x89,0xe9,0xe8};
constexpr uint8_t ObserverAFFrameCopy[]={0x48,0x89,0xdf,0x48,0x83,0xc7,0x48,0x31,0xc9,0x49,0x83,0xff,0xb8,0x49,0x0f,0x42,0xcf,0x48,0x8b,0x75,0xb0,0x4c,0x89,0xfa,0xe8};
constexpr uint8_t ObserverAFPost[]={0x49,0x8b,0xbe,0xb8,0x00,0x00,0x00,0xbe,0x30,0x00,0x00,0x00,0x48,0x89,0xda,0x4c,0x89,0xe9,0xe8,0xd5,0x27,0x07,0x00,0xeb,0x3d};
constexpr uint8_t ObserverAFDispose[]={0x48,0x8d,0x7d,0xb8,0xe8,0x49,0xc0,0xfe,0xff};
} // namespace ObserverPinDetail
namespace ObserverPinDetail {
inline ObserverPinStatus parseObserverImage(const void *image,size_t size,ObserverPins &out,bool entryRouted) {
    using namespace ObserverPinDetail;out={};
    const auto *b=static_cast<const uint8_t *>(image);
    const uintptr_t base=reinterpret_cast<uintptr_t>(image);
    if (!b || base%4 || size<32 || base>UINTPTR_MAX-size) return ObserverPinStatus::Input;
    if (u32(b)!=0xfeedfacf || u32(b+4)!=0x1000007 || u32(b+8)!=3 || u32(b+12)!=11)
        return ObserverPinStatus::MachO;
    const size_t count=u32(b+16),commands=u32(b+20),end=32+commands;
    if (!count || commands>8192-32 || commands>size-32 || count>commands/8)
        return ObserverPinStatus::MachO;
    size_t at=32;unsigned uuids=0,texts=0,sections=0;
    for (size_t n=0;n<count;++n) {
        if (!range(at,8,end)) return ObserverPinStatus::MachO;
        const uint32_t command=u32(b+at),length=u32(b+at+4);
        if (length<8 || length%8 || !range(at,length,end)) return ObserverPinStatus::MachO;
        if (command==0x1b) {
            if (++uuids!=1 || length!=24 || memcmp(b+at+8,UUID,16)) return ObserverPinStatus::UUID;
        } else if (command==0x19) {
            if (length<72) return ObserverPinStatus::MachO;
            const size_t sects=u32(b+at+64);
            if (sects>(length-72)/80 || sects*80!=length-72) return ObserverPinStatus::MachO;
            if (name(b+at+8,"__TEXT")) {
                const uint64_t address=u64(b+at+24),span=u64(b+at+32);
                // File offsets belong to the enclosing KC after OpenCore's
                // KcKextApplyFileDelta. Reads here use only the caller-owned
                // mapped base and checked VM-relative offsets, never fileoff.
                if (++texts!=1 || span<0xf5e56 || span>size ||
                    address>UINT64_MAX-span || !(u32(b+at+56)&4) || !(u32(b+at+60)&4))
                    return ObserverPinStatus::Text;
                for (size_t k=0;k<sects;++k) {
                    const uint8_t *s=b+at+72+80*k;
                    if (name(s,"__text")) {
                        const uint64_t sa=u64(s+32),sn=u64(s+40);
                        if (++sections!=1 || !name(s+16,"__TEXT") || sa<address ||
                            sa-address!=0xeb0 || sn!=0xf5e56-0xeb0 ||
                            !range(0xeb0,static_cast<size_t>(sn),static_cast<size_t>(span)) ||
                            !(u32(s+64)&0x80000000U)) return ObserverPinStatus::Text;
                    }
                }
            }
        }
        at+=length;
    }
    if (at!=end) return ObserverPinStatus::MachO;
    if (uuids!=1) return ObserverPinStatus::UUID;
    if (texts!=1 || sections!=1) return ObserverPinStatus::Text;
    if (!range(0xb19e2,sizeof(ObserverEntryGuard),size) ||
        !range(0xb3804,sizeof(ObserverSyncGuard),size) ||
        !range(0x42c2a,sizeof(ObserverPeerGuard),size) ||
        !range(0x6c602,sizeof(ObserverRemoveGuard),size) ||
        !range(0xb0778,sizeof(ObserverRoleGuard),size) ||
        !range(0xb0872,sizeof(ObserverNameGuard),size) ||
        !range(0x3f170,sizeof(ObserverAFPrefix),size) ||
        !range(0x3f19c,sizeof(ObserverAFAllocate),size) ||
        !range(0x3f1af,sizeof(ObserverAFHeaderCopy),size) ||
        !range(0x3f1d9,sizeof(ObserverAFFrameCopy),size) ||
        !range(0x3f1f6,sizeof(ObserverAFPost),size) ||
        !range(0x3f24c,sizeof(ObserverAFDispose),size)) return ObserverPinStatus::Text;
    if ((!entryRouted && memcmp(b+0xb19e2,ObserverEntryGuard,sizeof(ObserverEntryGuard))) ||
        memcmp(b+0xb3804,ObserverSyncGuard,sizeof(ObserverSyncGuard)) ||
        memcmp(b+0x42c2a,ObserverPeerGuard,sizeof(ObserverPeerGuard)) ||
        memcmp(b+0x6c602,ObserverRemoveGuard,sizeof(ObserverRemoveGuard)) ||
        memcmp(b+0xb0778,ObserverRoleGuard,sizeof(ObserverRoleGuard)) ||
        memcmp(b+0xb0872,ObserverNameGuard,sizeof(ObserverNameGuard)) ||
        memcmp(b+0x3f170,ObserverAFPrefix,sizeof(ObserverAFPrefix)) ||
        memcmp(b+0x3f19c,ObserverAFAllocate,sizeof(ObserverAFAllocate)) ||
        memcmp(b+0x3f1af,ObserverAFHeaderCopy,sizeof(ObserverAFHeaderCopy)) ||
        memcmp(b+0x3f1d9,ObserverAFFrameCopy,sizeof(ObserverAFFrameCopy)) ||
        memcmp(b+0x3f1f6,ObserverAFPost,sizeof(ObserverAFPost)) ||
        memcmp(b+0x3f24c,ObserverAFDispose,sizeof(ObserverAFDispose)))
        return ObserverPinStatus::Guard;
    out={base,base+0xb19e2,size,base+0xb0778,base+0xb0872};return ObserverPinStatus::Passed;
}
} // namespace ObserverPinDetail
inline ObserverPinStatus initializeObserverPins(const void *image,size_t size,ObserverPins &out) {
    return ObserverPinDetail::parseObserverImage(image,size,out,false);
}
// The owner already installed this component's entry route. Recheck header,
// source/caller/leaf code while deliberately excluding only OUR patched entry.
// This is not an independent route ownership or readable-VM proof.
inline ObserverPinStatus revalidateObserverSources(const ObserverPins &installed) {
    ObserverPins checked;
    const auto s=ObserverPinDetail::parseObserverImage(reinterpret_cast<const void *>(installed.base),
                                                       installed.extent,checked,true);
    if (s!=ObserverPinStatus::Passed) return s;
    return checked.base==installed.base && checked.entry==installed.entry &&
        checked.extent==installed.extent && checked.role==installed.role &&
        checked.bsdName==installed.bsdName?ObserverPinStatus::Passed:ObserverPinStatus::Guard;
}
// Used only during sleepable install on the actual mapped/relocated image.
// No target probing/dereference; overflow and non-E8 call shapes fail closed.
inline bool observerRelativeCallTarget(const void *image,size_t size,size_t call,uintptr_t &out) {
    using namespace ObserverPinDetail;out=0;
    const auto *b=static_cast<const uint8_t *>(image);
    const auto base=reinterpret_cast<uintptr_t>(image);
    if (!b || base>UINTPTR_MAX-size || !range(call,5,size) || b[call]!=0xe8) return false;
    int32_t displacement;memcpy(&displacement,b+call+1,4);
    const auto next=base+call+5;
    if (displacement>=0) {
        const auto delta=static_cast<uintptr_t>(displacement);
        if (next>UINTPTR_MAX-delta) return false;out=next+delta;
    } else {
        const auto delta=static_cast<uintptr_t>(-static_cast<int64_t>(displacement));
        if (next<delta) return false;out=next-delta;
    }
    return out!=0;
}
} // namespace AWDLKernel
#endif
