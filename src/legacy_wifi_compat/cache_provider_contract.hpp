// Fixed El Cap IO80211 cache-layout and lifetime contract. This guards only
// the pinned provider image; it does not establish cache identity semantics.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_CACHE_PROVIDER_CONTRACT_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_CACHE_PROVIDER_CONTRACT_HPP

#include "provider_contract.hpp"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace LegacyWiFi { namespace CacheProviderContract {

namespace P = ProviderContract;

// The full SHA pins the retained source artifact in the offline verifier.
// Runtime verification binds the loaded image by UUID and exact guarded code.
constexpr char SourceSHA256[] =
    "8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0";
constexpr uint8_t SourceUUID[16] = {
    0xb6,0xa4,0x3e,0xdc,0x47,0xe9,0x3d,0xb8,
    0x98,0x87,0x81,0x2d,0x1c,0x77,0xf3,0x8c
};

constexpr size_t ManagerCacheHeadOffset = 0x18;
constexpr size_t PendingRequestHeadOffset = 0x10;
constexpr size_t ScanManagerInstanceSize = 0xb0;
constexpr size_t ScanManagerInstanceSizeInstructionOffset = 0x5f60f;
constexpr size_t CacheNodeSize = 0xc0;
constexpr size_t CacheNodeNextOffset = 0x00;
constexpr size_t CacheNodePreviousLinkOffset = 0x08;
constexpr size_t CacheNodeReferenceCountOffset = 0x10;
constexpr size_t CacheNodeScanResultOffset = 0x18;
constexpr size_t CacheNodeScanResultSize = 0x98;
constexpr size_t CacheNodeBSSIDOffset = 0x34;
constexpr size_t CacheNodeSSIDLengthOffset = 0x78;
constexpr size_t CacheNodeSSIDBytesOffset = 0x79;
constexpr size_t CacheNodeIELengthOffset = 0xa2;
constexpr size_t CacheNodeIEPointerOffset = 0xa8;
constexpr size_t CacheNodeAgeOffset = 0xb8;
constexpr size_t RequestCacheReferenceOwnerOffset = 0x1288;
constexpr size_t RequestPIDResultQueueOffset = 0x1290;
constexpr size_t RequestCacheReferenceSize = 0x18;
constexpr size_t RequestCacheReferenceNodeOffset = 0x10;
constexpr size_t FinishAttachManagerInitCall = 0x57a41;
constexpr size_t ManagerInitReturn = 0x57a46;
constexpr size_t FinishAttachManagerInitReturnPC = ManagerInitReturn;
constexpr size_t Apple80211IoctlSetStart = 0x55460;
constexpr size_t Apple80211IoctlSetEnd = 0x55519;
constexpr size_t Apple80211IoctlSetNextSymbol = 0x5551a;
constexpr size_t SetHandlerTableOffset = 0xa30e0;
constexpr size_t SetHandlerTableCountOffset = 0xa3840;
constexpr uint32_t SetHandlerTableCountValue = 236;
constexpr size_t DisassociateHandlerCallInstruction = 0x554e4;
constexpr uintptr_t DisassociateHandlerReturnPC = 0x554e6;

enum Function : uint8_t {
    ManagerInit,
    PurgeTimeout,
    ManagerFree,
    GetCachedResults,
    GetScanResult,
    UpdateCache,
    ScanDone,
    CachePurge,
    ReleaseRequestNode,
    ReleaseCacheNode,
    InterfaceDetach,
    InterfaceFinishAttach,
    Apple80211IoctlSet,
    FunctionCount
};

enum Import : uint8_t {
    IOLog,
    IOMalloc,
    IOFree,
    Bzero,
    Memcpy,
    Memcmp,
    ClockGetCalendarNanotime,
    ProcSelfPID,
    ProcSelfName,
    TimerEventSource,
    StackCheckFail,
    IfnetRemoveMulticast,
    IfmaddrRelease,
    EthernetInterfaceVTable,
    IfnetIndex,
    IfnetAddMulticast,
    IfnetLLAddr,
    IfnetType,
    RegisterPrioritySleepWakeInterest,
    BufKernelAddrpermAddr,
    IfnetSetEflags,
    ProcSelf,
    ProcIs64Bit,
    ProcRele,
    ImportCount
};

constexpr const char *ImportNames[ImportCount] = {
    "_IOLog", "_IOMalloc", "_IOFree", "_bzero", "_memcpy", "_memcmp",
    "_clock_get_calendar_nanotime", "_proc_selfpid", "_proc_selfname",
    "__ZN18IOTimerEventSource16timerEventSourceEP8OSObjectPFvS1_PS_E",
    "___stack_chk_fail", "_ifnet_remove_multicast", "_ifmaddr_release",
    "__ZTV19IOEthernetInterface", "_ifnet_index", "_ifnet_add_multicast",
    "_ifnet_lladdr", "_ifnet_type", "_registerPrioritySleepWakeInterest",
    "_buf_kernel_addrperm_addr", "_ifnet_set_eflags", "_proc_self",
    "_proc_is64bit", "_proc_rele"
};

struct Symbols {
    uintptr_t addresses[FunctionCount];
};

struct Imports {
    uintptr_t addresses[ImportCount];
};

enum TerminalKind : uint8_t {
    Return,
    ImportedCall,
    ImportedJump,
    InternalJump,
    IndirectJump
};

struct FunctionContract {
    const char *name;
    size_t start;
    size_t end;
    size_t nextSymbol;
    size_t terminal;
    TerminalKind terminalKind;
    uint8_t terminalImport;
    uintptr_t terminalTarget;
    const uint8_t *sha256;
};

constexpr uint8_t ManagerInitSHA[32] = {
    0x14,0xa1,0x63,0x80,0xb4,0x62,0xfe,0x3c,0x72,0x67,0x0b,0x3c,0x71,0x0a,0x12,0xbb,
    0x9b,0xb8,0x77,0xd3,0x0a,0x0b,0x3b,0xd7,0x91,0xc5,0xaf,0x20,0x3b,0xb6,0xaa,0x14
};
constexpr uint8_t PurgeTimeoutSHA[32] = {
    0x6f,0xa9,0xe5,0xb0,0x99,0x3f,0x93,0xad,0x29,0xf4,0x88,0x27,0x38,0xef,0x51,0xeb,
    0x8b,0xea,0xbb,0xf7,0x5a,0xfc,0x05,0x76,0x49,0xbd,0x08,0x24,0x83,0xa2,0x3c,0x83
};
constexpr uint8_t ManagerFreeSHA[32] = {
    0xed,0xcf,0x3f,0x1c,0xcd,0xc6,0xb0,0x6a,0xa4,0x32,0x72,0x58,0xfe,0x12,0x35,0x66,
    0xb4,0xe2,0xb5,0x7c,0xeb,0xb5,0xae,0x86,0x2a,0x87,0xf4,0x07,0x39,0xad,0x1d,0xf9
};
constexpr uint8_t GetCachedResultsSHA[32] = {
    0x53,0xe1,0x15,0xec,0x94,0x47,0xbd,0x37,0x14,0x29,0xe7,0x95,0x6d,0x2d,0x97,0x5b,
    0x31,0xbc,0x48,0xd0,0x2a,0x26,0xc9,0x1f,0x53,0xee,0x9a,0x16,0x95,0x60,0x8d,0x79
};
constexpr uint8_t GetScanResultSHA[32] = {
    0xd2,0xf8,0xfe,0xc6,0xac,0x15,0x0b,0xa5,0x25,0x68,0x15,0x24,0x0d,0xce,0x4f,0x3a,
    0x4e,0x3e,0x2e,0xae,0x8e,0xc0,0xb2,0xbc,0xec,0xe9,0x17,0x18,0xc6,0xc3,0x8b,0xe3
};
constexpr uint8_t UpdateCacheSHA[32] = {
    0x49,0x73,0xb4,0x68,0x38,0xd0,0x77,0xb5,0x88,0xf6,0x92,0x16,0xe3,0xe0,0x6b,0x7a,
    0xcc,0x1b,0xf4,0x31,0x00,0x92,0x0b,0x08,0xbb,0xc2,0x72,0x5c,0x42,0x98,0x67,0xb0
};
constexpr uint8_t ScanDoneSHA[32] = {
    0x13,0x4f,0xbc,0x1e,0x9b,0x7b,0x56,0x0d,0x6a,0x48,0x3e,0x16,0x91,0xc7,0x00,0xc3,
    0x6b,0xc6,0x7b,0xd0,0xb7,0x36,0x17,0x53,0x3b,0x87,0xec,0x25,0x6e,0xe7,0xdd,0x58
};
constexpr uint8_t CachePurgeSHA[32] = {
    0x43,0x28,0x83,0xd6,0x8b,0x72,0x82,0x84,0x86,0xf6,0x58,0x1a,0x4d,0x93,0x9e,0x1e,
    0x51,0x2f,0xf3,0x1b,0x5e,0x34,0xb3,0x22,0x0f,0x05,0xb4,0x2f,0xff,0xd7,0x24,0x6e
};
constexpr uint8_t ReleaseRequestNodeSHA[32] = {
    0x2c,0xe7,0xce,0x8c,0x59,0xf4,0xee,0x13,0xa4,0xc0,0x63,0xc4,0xee,0x59,0xa2,0xe1,
    0xef,0xc6,0x40,0xfa,0xdc,0xac,0xc6,0xbe,0x38,0x38,0x22,0x4b,0x23,0x5f,0x9e,0x38
};
constexpr uint8_t ReleaseCacheNodeSHA[32] = {
    0x35,0xfd,0x56,0x4b,0x46,0x8c,0x2e,0xe5,0x0a,0x23,0xc4,0x7a,0x9e,0x90,0xb6,0x84,
    0xeb,0x75,0x6b,0xd1,0x37,0xd2,0xb1,0x7b,0xa6,0x20,0x40,0xd2,0x0a,0x04,0xd9,0x42
};
constexpr uint8_t InterfaceDetachSHA[32] = {
    0x4a,0x8f,0x52,0xe5,0x2a,0xdc,0xa3,0x08,0x97,0xaa,0x4f,0x23,0xde,0x3e,0x17,0x87,
    0x4b,0x6d,0xd9,0x98,0xf3,0x03,0xb6,0x59,0x0f,0x11,0xa0,0x9c,0x2a,0x2c,0xbf,0x73
};
constexpr uint8_t InterfaceFinishAttachSHA[32] = {
    0x12,0xb1,0xc4,0x70,0x5c,0x59,0xc3,0x9a,0x0f,0x12,0x4c,0xdc,0x6b,0x97,0xc8,0x64,
    0x11,0xe1,0xca,0x17,0x66,0x0c,0x76,0x2c,0x64,0xaf,0xc8,0x29,0x4f,0x82,0xf7,0xa4
};
constexpr uint8_t Apple80211IoctlSetSHA[32] = {
    0x0f,0xa6,0xc4,0xb0,0x94,0x6a,0xd3,0x68,0x4a,0x07,0xd0,0xf5,0xfe,0x37,0xd9,0xfc,
    0xe6,0xb8,0x84,0x15,0xa3,0xf1,0x6d,0x0e,0x30,0xed,0x24,0x8f,0x5c,0x81,0x39,0x9e
};

constexpr FunctionContract Functions[FunctionCount] = {
    {"__ZN18IO80211ScanManager30initWithControllerAndInterfaceEP17IO80211ControllerP16IO80211Interface",0x5f70a,0x5f86e,0x5f86e,0x5f869,ImportedCall,StackCheckFail,0,ManagerInitSHA},
    {"__ZN18IO80211ScanManager17cachePurgeTimeoutEP8OSObjectP18IOTimerEventSource",0x5f86e,0x5f87a,0x5f87a,0x5f875,InternalJump,0,0x6203c,PurgeTimeoutSHA},
    {"__ZN18IO80211ScanManager4freeEv",0x5fc78,0x5fd45,0x5fd46,0x5fd3f,IndirectJump,0,0xa0,ManagerFreeSHA},
    {"__ZN18IO80211ScanManager20getCachedScanResultsEP20apple80211_scan_dataP23apple80211scan_req_nodeP10ether_addrj",0x60186,0x60435,0x60436,0x60434,Return,0,0,GetCachedResultsSHA},
    {"__ZN18IO80211ScanManager13getScanResultEPP22apple80211_scan_result",0x61b1e,0x61cc2,0x61cc2,0x61cbd,ImportedCall,StackCheckFail,0,GetScanResultSHA},
    {"__ZN18IO80211ScanManager11updateCacheEP25apple80211scan_cache_nodeP23apple80211scan_req_node",0x61cc2,0x61d9e,0x61d9e,0x61d9d,Return,0,0,UpdateCacheSHA},
    {"__ZN18IO80211ScanManager8scanDoneEb",0x61d9e,0x6203b,0x6203c,0x6203a,Return,0,0,ScanDoneSHA},
    {"__ZN18IO80211ScanManager10cachePurgeEb",0x6203c,0x62302,0x62302,0x62301,Return,0,0,CachePurgeSHA},
    {"__ZL15_releaseReqNodeP23apple80211scan_req_node",0x625ce,0x6265a,0x6265a,0x62655,ImportedJump,IOFree,0,ReleaseRequestNodeSHA},
    {"__ZL17_releaseCacheNodeP25apple80211scan_cache_node",0x6265a,0x626aa,0x626aa,0x626a5,ImportedJump,IOFree,0,ReleaseCacheNodeSHA},
    {"__ZN16IO80211Interface23detachFromDataLinkLayerEjPv",0x58126,0x5819e,0x5819e,0x58198,IndirectJump,0,0x9b8,InterfaceDetachSHA},
    {"__ZN16IO80211Interface27finishAttachToDataLinkLayerEv",0x578ba,0x57b63,0x57b64,0x57b5e,ImportedCall,StackCheckFail,0,InterfaceFinishAttachSHA},
    {"__ZN17IO80211Controller20apple80211_ioctl_setEP16IO80211InterfaceP23IO80211VirtualInterfaceP7__ifnetPv",Apple80211IoctlSetStart,Apple80211IoctlSetEnd,Apple80211IoctlSetNextSymbol,Apple80211IoctlSetEnd-1,Return,0,0,Apple80211IoctlSetSHA}
};

struct RelocationCall {
    size_t instruction;
    Import target;
    uint8_t opcode;
};

constexpr RelocationCall ExternalCalls[] = {
    {0x5f7f1,IOLog,0xe8}, {0x5f767,TimerEventSource,0xe8}, {0x5f869,StackCheckFail,0xe8},
    {0x603bf,IOMalloc,0xe8}, {0x601ae,ClockGetCalendarNanotime,0xe8},
    {0x60207,Memcmp,0xe8}, {0x602af,Memcmp,0xe8}, {0x602e0,Memcmp,0xe8}, {0x6032e,Memcmp,0xe8},
    {0x61c68,IOFree,0xe8}, {0x61c34,IOLog,0xe8}, {0x61cbd,StackCheckFail,0xe8},
    {0x61ba4,ClockGetCalendarNanotime,0xe8}, {0x61c04,ProcSelfName,0xe8}, {0x61b46,ProcSelfPID,0xe8},
    {0x61cff,Memcmp,0xe8},
    {0x61f73,IOFree,0xe8}, {0x62000,IOLog,0xe8}, {0x61e2b,IOMalloc,0xe8},
    {0x61e71,IOMalloc,0xe8}, {0x61ee0,IOMalloc,0xe8}, {0x61e44,Bzero,0xe8},
    {0x61dc1,ClockGetCalendarNanotime,0xe8}, {0x61e59,Memcpy,0xe8}, {0x61ea9,Memcpy,0xe8},
    {0x6207e,IOLog,0xe8}, {0x620ee,IOLog,0xe8}, {0x62206,IOLog,0xe8},
    {0x6229f,IOLog,0xe8}, {0x622e4,IOLog,0xe8}, {0x62097,ClockGetCalendarNanotime,0xe8},
    {0x621db,Memcpy,0xe8}, {0x62224,Memcpy,0xe8},
    {0x625e6,IOFree,0xe8}, {0x62611,IOFree,0xe8}, {0x62655,IOFree,0xe9},
    {0x62692,IOFree,0xe8}, {0x626a5,IOFree,0xe9}, {0x6267a,IOLog,0xe8},
    {0x58145,IfnetRemoveMulticast,0xe8}, {0x58151,IfmaddrRelease,0xe8},
    {0x57926,Bzero,0xe8}, {0x5793e,IfnetIndex,0xe8}, {0x57959,Memcpy,0xe8},
    {0x5796b,IfnetAddMulticast,0xe8}, {0x57973,IfnetLLAddr,0xe8},
    {0x57982,IfnetType,0xe8}, {0x579a1,RegisterPrioritySleepWakeInterest,0xe8},
    {0x579b4,BufKernelAddrpermAddr,0xe8}, {0x579cf,BufKernelAddrpermAddr,0xe8},
    {0x579da,BufKernelAddrpermAddr,0xe8}, {0x579f1,BufKernelAddrpermAddr,0xe8},
    {0x57a0b,IOLog,0xe8}, {0x57aca,IOLog,0xe8}, {0x57adc,IfnetSetEflags,0xe8},
    {0x57b5e,StackCheckFail,0xe8},
    {0x5547a,ProcSelf,0xe8}, {0x5548f,ProcIs64Bit,0xe8}, {0x5549a,ProcRele,0xe8}
};
constexpr size_t ExternalCallCount = sizeof(ExternalCalls)/sizeof(ExternalCalls[0]);

// The indirect tail dispatch reads the IOEthernetInterface vtable from this
// external relocation slot. At runtime the slot must contain the resolved
// address of that vtable, not a synthetic or merely non-null pointer.
struct ExternalPointer {
    size_t offset;
    Import target;
};
constexpr ExternalPointer ExternalPointers[] = {
    {0x98090,EthernetInterfaceVTable}
};
constexpr size_t ExternalPointerCount = sizeof(ExternalPointers)/sizeof(ExternalPointers[0]);

// Manager release is an indirect vtable call through OSObject's release slot.
// The body fingerprint pins its surrounding control flow; this records the
// exact opcode/slot pair separately for review and mutation checks.
struct IndirectCall {
    size_t instruction;
    uint8_t vtableSlot;
};
constexpr IndirectCall IndirectCalls[] = {
    {0x58170,0x28}
};
constexpr size_t IndirectCallCount = sizeof(IndirectCalls)/sizeof(IndirectCalls[0]);

struct InternalBranch {
    size_t instruction;
    uintptr_t targetOffset;
    uint8_t opcode;
};

// Calls linking cache lifetime routes and the SET dispatcher log target. The
// complete body fingerprints pin all other instructions.
constexpr InternalBranch CacheBranches[] = {
    {0x5f840,0x537a6,0xe8}, {0x5f875,0x6203c,0xe9},
    {0x5fce5,0x625ce,0xe8}, {0x5fd0f,0x6265a,0xe8},
    {0x61c91,0x625ce,0xe8}, {0x61d6c,0x6265a,0xe8},
    {0x61ed1,0x61cc2,0xe8},
    {0x62117,0x625ce,0xe8}, {0x62159,0x6265a,0xe8}, {0x62273,0x6265a,0xe8},
    {0x62642,0x6265a,0xe8},
    {0x57990,0x57b64,0xe8}, {0x57a41,0x5f70a,0xe8},
    {0x57aaf,0x5c4e8,0xe8}, {0x57af3,0x57dd8,0xe8},
    {0x57b0f,0x6a886,0xe8}, {0x57b2f,0x56dea,0xe8},
    {0x55500,0x53e34,0xe8}
};
constexpr size_t CacheBranchCount = sizeof(CacheBranches)/sizeof(CacheBranches[0]);

struct PaddingByte { size_t offset; uint8_t value; };
constexpr PaddingByte Padding[] = {
    {0x5fd45,0x90}, {0x60435,0x90}, {0x6203b,0x90}, {0x57b63,0x90},
    {0x55519,0x90}
};

namespace detail {

struct Sha256Context {
    uint32_t state[8];
    uint64_t byteCount;
    uint8_t block[64];
    size_t used;
};

inline uint32_t rotateRight(uint32_t value, unsigned amount) {
    return (value >> amount) | (value << (32U-amount));
}

inline void sha256Transform(Sha256Context *context, const uint8_t block[64]) {
    static const uint32_t constants[64] = {
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
    };
    uint32_t words[64];
    for (size_t index=0; index<16; ++index) {
        const size_t offset=index*4;
        words[index]=(static_cast<uint32_t>(block[offset])<<24) |
            (static_cast<uint32_t>(block[offset+1])<<16) |
            (static_cast<uint32_t>(block[offset+2])<<8) |
            static_cast<uint32_t>(block[offset+3]);
    }
    for (size_t index=16; index<64; ++index) {
        const uint32_t x=words[index-15], y=words[index-2];
        const uint32_t sigma0=rotateRight(x,7)^rotateRight(x,18)^(x>>3);
        const uint32_t sigma1=rotateRight(y,17)^rotateRight(y,19)^(y>>10);
        words[index]=words[index-16]+sigma0+words[index-7]+sigma1;
    }
    uint32_t a=context->state[0],b=context->state[1],c=context->state[2],d=context->state[3];
    uint32_t e=context->state[4],f=context->state[5],g=context->state[6],h=context->state[7];
    for (size_t index=0; index<64; ++index) {
        const uint32_t sum1=rotateRight(e,6)^rotateRight(e,11)^rotateRight(e,25);
        const uint32_t choice=(e&f)^((~e)&g);
        const uint32_t temp1=h+sum1+choice+constants[index]+words[index];
        const uint32_t sum0=rotateRight(a,2)^rotateRight(a,13)^rotateRight(a,22);
        const uint32_t majority=(a&b)^(a&c)^(b&c);
        const uint32_t temp2=sum0+majority;
        h=g;g=f;f=e;e=d+temp1;d=c;c=b;b=a;a=temp1+temp2;
    }
    context->state[0]+=a;context->state[1]+=b;context->state[2]+=c;context->state[3]+=d;
    context->state[4]+=e;context->state[5]+=f;context->state[6]+=g;context->state[7]+=h;
}

inline void sha256Init(Sha256Context *context) {
    const uint32_t initial[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
                               0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};
    memcpy(context->state,initial,sizeof(initial));
    context->byteCount=0;context->used=0;
}

inline void sha256Byte(Sha256Context *context,uint8_t value) {
    context->block[context->used++]=value;
    ++context->byteCount;
    if (context->used==sizeof(context->block)) {
        sha256Transform(context,context->block);
        context->used=0;
    }
}

inline void sha256Finish(Sha256Context *context,uint8_t digest[32]) {
    const uint64_t bitCount=context->byteCount*8;
    context->block[context->used++]=0x80;
    if (context->used>56) {
        while(context->used<64) context->block[context->used++]=0;
        sha256Transform(context,context->block);
        context->used=0;
    }
    while(context->used<56) context->block[context->used++]=0;
    for (int shift=56;shift>=0;shift-=8)
        context->block[context->used++]=static_cast<uint8_t>(bitCount>>shift);
    sha256Transform(context,context->block);
    for (size_t index=0;index<8;++index) {
        digest[index*4]=static_cast<uint8_t>(context->state[index]>>24);
        digest[index*4+1]=static_cast<uint8_t>(context->state[index]>>16);
        digest[index*4+2]=static_cast<uint8_t>(context->state[index]>>8);
        digest[index*4+3]=static_cast<uint8_t>(context->state[index]);
    }
}

inline bool isRelocationByte(size_t offset) {
    for (size_t index=0;index<ExternalCallCount;++index) {
        const size_t site=ExternalCalls[index].instruction;
        if (offset>site && offset<site+5) return true;
    }
    return false;
}

inline bool verifyFingerprint(const P::Image &image,const FunctionContract &function) {
    if (function.end<function.start || !P::range(image,function.start,function.end-function.start))
        return false;
    Sha256Context context {};
    sha256Init(&context);
    for (size_t offset=function.start;offset<function.end;++offset)
        sha256Byte(&context,isRelocationByte(offset)?0:image.bytes[offset]);
    uint8_t digest[32];
    sha256Finish(&context,digest);
    return memcmp(digest,function.sha256,sizeof(digest))==0;
}

inline bool relativeBranch(const P::Image &image,size_t instruction,
                           uintptr_t target,uint8_t opcode) {
    if (!P::range(image,instruction,5) || image.bytes[instruction]!=opcode ||
        instruction>UINTPTR_MAX-image.base-5) return false;
    const uintptr_t returnPC=image.base+instruction+5;
    int64_t expected=0;
    if (target>=returnPC) {
        const uint64_t distance=target-returnPC;
        if (distance>static_cast<uint64_t>(INT32_MAX)) return false;
        expected=static_cast<int64_t>(distance);
    } else {
        const uint64_t distance=returnPC-target;
        if (distance>0x80000000ULL) return false;
        expected=-static_cast<int64_t>(distance);
    }
    int32_t actual=0;
    memcpy(&actual,image.bytes+instruction+1,sizeof(actual));
    return actual==expected;
}

inline uintptr_t importTarget(const Imports &imports,Import target) {
    return imports.addresses[static_cast<size_t>(target)];
}

inline bool verifyExternalBranch(const P::Image &image,const Imports &imports,
                                 const RelocationCall &branch) {
    const uintptr_t target=importTarget(imports,branch.target);
    if (!target || (target>=image.base && target-image.base<image.size)) return false;
    if (branch.opcode==0xe8) return P::externalCall(image,branch.instruction,target);
    if (branch.opcode==0xe9) return relativeBranch(image,branch.instruction,target,0xe9);
    return false;
}

inline bool verifyTerminal(const P::Image &image,const Imports &imports,
                           const FunctionContract &function) {
    switch(function.terminalKind) {
        case Return:
            return function.terminal+1==function.end && P::range(image,function.terminal,1) &&
                image.bytes[function.terminal]==0xc3;
        case ImportedCall:
        case ImportedJump: {
            const uint8_t opcode=function.terminalKind==ImportedCall?0xe8:0xe9;
            if (function.terminal+5!=function.end || !P::range(image,function.terminal,5) ||
                image.bytes[function.terminal]!=opcode) return false;
            for (size_t index=0;index<ExternalCallCount;++index) {
                const RelocationCall &branch=ExternalCalls[index];
                if (branch.instruction==function.terminal &&
                    static_cast<uint8_t>(branch.target)==function.terminalImport)
                    return verifyExternalBranch(image,imports,branch);
            }
            return false;
        }
        case InternalJump:
            return function.terminal+5==function.end &&
                relativeBranch(image,function.terminal,image.base+function.terminalTarget,0xe9);
        case IndirectJump: {
            if (function.terminal+6!=function.end ||
                !P::range(image,function.terminal,6) ||
                image.bytes[function.terminal]!=0xff ||
                image.bytes[function.terminal+1]!=0xa0 ||
                function.terminalTarget>UINT32_MAX) return false;
            uint32_t slot=0;
            memcpy(&slot,image.bytes+function.terminal+2,sizeof(slot));
            return slot==static_cast<uint32_t>(function.terminalTarget);
        }
    }
    return false;
}

inline bool verifySetDispatcherDataReferences(const P::Image &image) {
    uintptr_t firstCountTarget=0, tableTarget=0, secondCountTarget=0;
    if (!P::ripRelativeTarget(image,0x554b0,6,2,firstCountTarget) ||
        !P::ripRelativeTarget(image,0x554bc,7,3,tableTarget) ||
        !P::ripRelativeTarget(image,0x554ee,6,2,secondCountTarget) ||
        firstCountTarget!=image.base+SetHandlerTableCountOffset ||
        secondCountTarget!=image.base+SetHandlerTableCountOffset ||
        tableTarget!=image.base+SetHandlerTableOffset ||
        !P::range(image,SetHandlerTableCountOffset,sizeof(uint32_t))) return false;
    uint32_t count=0;
    memcpy(&count,image.bytes+SetHandlerTableCountOffset,sizeof(count));
    return count==SetHandlerTableCountValue;
}

} // namespace detail

inline bool verify(const P::Image &image,const uint8_t providerUUID[16],
                   const Symbols &symbols,const Imports &imports) {
    if (!providerUUID || !image.bytes || !image.base ||
        image.size>UINTPTR_MAX-image.base ||
        memcmp(providerUUID,SourceUUID,sizeof(SourceUUID))!=0) return false;

    if (!detail::verifySetDispatcherDataReferences(image)) return false;

    const uint8_t managerSizeInstruction[] = {0xb9,0xb0,0x00,0x00,0x00};
    if (!P::bytes(image,ScanManagerInstanceSizeInstructionOffset,managerSizeInstruction))
        return false;

    for (size_t index=0;index<FunctionCount;++index) {
        const FunctionContract &function=Functions[index];
        if (symbols.addresses[index]!=image.base+function.start ||
            function.end<=function.start || function.nextSymbol<function.end ||
            !P::range(image,function.start,function.end-function.start) ||
            !detail::verifyFingerprint(image,function) ||
            !detail::verifyTerminal(image,imports,function)) return false;
    }

    for (size_t index=0;index<ExternalCallCount;++index)
        if (!detail::verifyExternalBranch(image,imports,ExternalCalls[index])) return false;

    for (size_t index=0;index<ExternalPointerCount;++index) {
        const ExternalPointer &pointer=ExternalPointers[index];
        const uintptr_t target=detail::importTarget(imports,pointer.target);
        if (!target || (target>=image.base && target-image.base<image.size) ||
            !P::range(image,pointer.offset,sizeof(target))) return false;
        uintptr_t actual=0;
        memcpy(&actual,image.bytes+pointer.offset,sizeof(actual));
        if (actual!=target) return false;
    }

    for (size_t index=0;index<IndirectCallCount;++index) {
        const IndirectCall &call=IndirectCalls[index];
        const uint8_t expected[]={0xff,0x50,call.vtableSlot};
        if (!P::bytes(image,call.instruction,expected)) return false;
    }

    for (size_t index=0;index<CacheBranchCount;++index) {
        const InternalBranch &branch=CacheBranches[index];
        const uintptr_t target=image.base+branch.targetOffset;
        if (branch.opcode==0xe8) {
            if (!P::call(image,branch.instruction,target)) return false;
        } else if (branch.opcode==0xe9) {
            if (!detail::relativeBranch(image,branch.instruction,target,0xe9)) return false;
        } else {
            return false;
        }
    }

    for (size_t index=0;index<sizeof(Padding)/sizeof(Padding[0]);++index) {
        const PaddingByte &padding=Padding[index];
        if (!P::range(image,padding.offset,1) || image.bytes[padding.offset]!=padding.value)
            return false;
    }
    return true;
}

// This proves the caller is the pinned provider's indirect handler-dispatch
// instruction and that the active handler is this image's SET22 symbol. It
// does not independently prove which table slot selected that handler; the
// routed handler must also validate request type 22. The caller must first
// accept both CacheProviderContract::verify and ProviderContract::verify.
inline bool isCanonicalSetDisassociateHandlerDispatch(
        const P::Image &image, uintptr_t returnPC, uintptr_t handlerAddress) {
    const uint8_t indirectCall[]={0xff,0xd0};
    if (!image.bytes || !image.base || image.size>UINTPTR_MAX-image.base ||
        !P::range(image,DisassociateHandlerCallInstruction,sizeof(indirectCall)) ||
        !P::range(image,P::Offsets[P::SetDisassociate],1) ||
        returnPC!=image.base+DisassociateHandlerReturnPC) return false;
    const uintptr_t expectedHandler=image.base+P::Offsets[P::SetDisassociate];
    return handlerAddress>=image.base && handlerAddress-image.base<image.size &&
        handlerAddress==expectedHandler &&
        P::bytes(image,DisassociateHandlerCallInstruction,indirectCall);
}

// The caller must have accepted this image with verify() before using this
// callsite proof. finishAttachToDataLinkLayer allocates/stores a new manager
// before this unique init call; the captured return PC distinguishes that
// provider-owned initialization from unrelated direct init calls.
inline bool isFreshFinishAttachManagerInitReturn(const P::Image &image,
                                                  uintptr_t returnPC,
                                                  const Symbols &symbols) {
    if (!image.bytes || !image.base || image.size>UINTPTR_MAX-image.base ||
        returnPC<image.base || returnPC-image.base!=FinishAttachManagerInitReturnPC ||
        !P::range(image,FinishAttachManagerInitCall,5)) return false;
    const uintptr_t expectedFinishAttach=image.base+Functions[InterfaceFinishAttach].start;
    const uintptr_t expectedManagerInit=image.base+Functions[ManagerInit].start;
    return symbols.addresses[InterfaceFinishAttach]==expectedFinishAttach &&
        symbols.addresses[ManagerInit]==expectedManagerInit &&
        P::call(image,FinishAttachManagerInitCall,symbols.addresses[ManagerInit]);
}

} } // namespace LegacyWiFi::CacheProviderContract
#endif
