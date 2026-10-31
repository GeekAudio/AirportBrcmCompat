#include "scoped_reset.hpp"
#include "native_control_bridge.hpp"
#include "../scan_kernel/kernel_identity.hpp"
#include "../scan_kernel/kernel_contracts.hpp"
#include <IOKit/IOCommandGate.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOLocks.h>
#include <kern/thread.h>
#include <machine/machine_routines.h>
#include <mach-o/loader.h>
#include <sys/errno.h>

// The old gated function's first14 bytes include a relative branch. Lilu copies
// its trampoline prologue without relocating branches. This exact PIC prefix
// bridge recreates those14 bytes and jumps to the untouched original tail.
// No descriptor, provider slot or class identity is fabricated.
extern "C" {
uintptr_t airport_awdl_original_gated_tail=0;
__attribute__((naked,noinline)) IOReturn airport_awdl_original_gated(
    OSObject *,void *,void *,void *,void *) {
    __asm__("pushq %rbp\n"
            "movq %rsp,%rbp\n"
            "cmpq $0,0xa0(%rsi)\n"
            "je 1f\n"
            "jmpq *_airport_awdl_original_gated_tail(%rip)\n"
            "1: xorl %eax,%eax\n"
            "popq %rbp\n"
            "retq\n");
}
}

namespace AWDLKernel { namespace ScopedResetBridge { namespace {
using Reset=void (*)(IOUserClient *);
constexpr const char *ResetSymbol="__ZN27IO80211AsyncEventUserClient11resetClientEv";
constexpr const char *GatedSymbol="__ZN23IO80211VirtualInterface29resetUserClientReferenceGatedEP8OSObjectPvS2_S2_S2_";
constexpr const char *RunSymbol="__ZN13IOCommandGate9runActionEPFiP8OSObjectPvS2_S2_S2_ES2_S2_S2_S2_";
constexpr uint8_t LegacyUUID[16]={0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab};
constexpr uint8_t ResetPrefix[]={0x55,0x48,0x89,0xe5,0x41,0x56,0x53,0x49,0x89,0xfe,
    0x48,0x8b,0x9f,0xf8,0,0,0};
constexpr uint8_t GatedBody[]={0x55,0x48,0x89,0xe5,0x48,0x83,0xbe,0xa0,0,0,0,0,
    0x74,0x13,0x48,0xc7,0x86,0xa0,0,0,0,0,0,0,0,0x48,0x89,0xf7,
    0xe8,0x05,0,0,0,0x31,0xc0,0x5d,0xc3,0x90};
ClientRegistry *registry=nullptr;
IOSimpleLock *scopeLock=nullptr;
Reset originalReset=nullptr;
bool attempted=false,enabled=false;
uintptr_t actionReturn=0;
uint32_t completeCount=0,noCallbackCount=0,retiredCount=0;
struct Scope {
    thread_t thread=THREAD_NULL;
    IOUserClient *client=nullptr;
    IOService *controller=nullptr,*provider=nullptr;
    bool consumed=false;
};
Scope *scopes[8] {};
bool image(mach_vm_address_t base,size_t size) {
    if (!base || base%alignof(mach_header_64) || size<sizeof(mach_header_64) ||
        base>UINTPTR_MAX-size) return false;
    auto *h=reinterpret_cast<const mach_header_64 *>(base);
    if (h->magic!=MH_MAGIC_64 || h->cputype!=CPU_TYPE_X86_64 || h->filetype!=MH_KEXT_BUNDLE ||
        h->sizeofcmds>8192-sizeof(*h) || h->sizeofcmds>size-sizeof(*h) ||
        h->ncmds>h->sizeofcmds/8) return false;
    size_t off=sizeof(*h),end=off+h->sizeofcmds;unsigned uuids=0,texts=0;
    for (uint32_t j=0;j<h->ncmds;++j) {
        if (off>end || end-off<sizeof(load_command)) return false;
        auto *c=reinterpret_cast<const load_command *>(base+off);
        if (c->cmdsize<sizeof(*c) || c->cmdsize%8 || c->cmdsize>end-off) return false;
        if (c->cmd==LC_UUID) {
            if (++uuids!=1 || c->cmdsize!=sizeof(uuid_command) ||
                memcmp(reinterpret_cast<const uuid_command *>(c)->uuid,LegacyUUID,16)) return false;
        }
        if (c->cmd==LC_SEGMENT_64) {
            if (c->cmdsize<sizeof(segment_command_64)) return false;
            auto *s=reinterpret_cast<const segment_command_64 *>(c);
            if (s->nsects>(c->cmdsize-sizeof(*s))/sizeof(section_64) ||
                sizeof(*s)+s->nsects*sizeof(section_64)!=c->cmdsize) return false;
            static const char text[16]="__TEXT";
            if (!memcmp(s->segname,text,16)) {
                if (++texts!=1 || !(s->initprot&4) || s->vmsize>size || s->vmsize<0xf5e56)
                    return false;
                bool found=false;auto *sections=reinterpret_cast<const section_64 *>(s+1);
                for (uint32_t k=0;k<s->nsects;++k) {
                    static const char code[16]="__text";
                    if (!memcmp(sections[k].sectname,code,16)) {
                        if (found || sections[k].addr<s->vmaddr || sections[k].addr-s->vmaddr!=0xeb0 ||
                            sections[k].size!=0xf5e56-0xeb0) return false;
                        found=true;
                    }
                }
                if (!found) return false;
            }
        }
        off+=c->cmdsize;
    }
    return off==end && uuids==1 && texts==1;
}
uintptr_t field(IOUserClient *client,size_t offset) {
    uintptr_t value=0;memcpy(&value,reinterpret_cast<const uint8_t *>(client)+offset,sizeof(value));
    return value;
}
bool enter(Scope &scope) {
    bool added=false;const auto irq=IOSimpleLockLockDisableInterrupt(scopeLock);
    bool duplicate=false;
    for (auto *node:scopes) if (node && node->client==scope.client) duplicate=true;
    if (!duplicate) for (auto &node:scopes) if (!node) {node=&scope;added=true;break;}
    IOSimpleLockUnlockEnableInterrupt(scopeLock,irq);return added;
}
void leave(Scope &scope) {
    const auto irq=IOSimpleLockLockDisableInterrupt(scopeLock);
    for (auto &node:scopes) if (node==&scope) {node=nullptr;break;}
    IOSimpleLockUnlockEnableInterrupt(scopeLock,irq);
}
// Only for this factory's retained, authorized type2 client when the normal
// gate action cannot be run without sleeping in a disabled/recursive teardown.
// The validated old reset's only remaining own-client effect is clearing f0;
// primary f8 is required NULL. No provider slot is ever written here.
bool retireOwnProvider(ClientWorkLease &lease) {
    auto **location=reinterpret_cast<void **>(reinterpret_cast<uint8_t *>(lease.client())+0xf0);
    void *expected=lease.provider();
    bool cleared=__atomic_compare_exchange_n(location,&expected,static_cast<void *>(nullptr),false,
                                             __ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    if (cleared || !expected) {__atomic_add_fetch(&retiredCount,1U,__ATOMIC_RELAXED);return true;}
    return false;
}
IOReturn wrappedGated(OSObject *owner,void *arg0,void *arg1,void *arg2,void *arg3) {
    const uintptr_t caller=reinterpret_cast<uintptr_t>(__builtin_return_address(0));
    if (__atomic_load_n(&enabled,__ATOMIC_ACQUIRE) && !ml_at_interrupt_context() &&
        caller==actionReturn && !arg1 && !arg2 && !arg3) {
        bool match=false;const auto irq=IOSimpleLockLockDisableInterrupt(scopeLock);
        for (auto *scope:scopes) if (scope && !scope->consumed && scope->thread==current_thread() &&
            scope->controller==owner && scope->provider==arg0) {
            scope->consumed=true;match=true;break;
        }
        IOSimpleLockUnlockEnableInterrupt(scopeLock,irq);
        if (match) return kIOReturnSuccess;
    }
    return airport_awdl_original_gated(owner,arg0,arg1,arg2,arg3);
}
IOReturn resetAction(OSObject *,void *argument,void *,void *,void *) {
    auto &lease=*static_cast<ClientWorkLease *>(argument);
    IOUserClient *client=lease.client();
    // A Closing tombstone is never removed in this bounded control-only test.
    // Ordinary external calls are rejected and cannot fall into the old table.
    if (field(client,0xf8) || (field(client,0xf0) && field(client,0xf0)!=
        reinterpret_cast<uintptr_t>(lease.provider()))) {
        __atomic_add_fetch(&retiredCount,1U,__ATOMIC_RELAXED);return kIOReturnNotReady;
    }
    if (!field(client,0xf0)) {originalReset(client);return kIOReturnSuccess;}
    Scope scope;scope.thread=current_thread();scope.client=client;
    scope.controller=lease.controller();scope.provider=lease.provider();
    auto *gate=lease.gate();auto *loop=lease.workLoop();
    auto *bound=gate?gate->getWorkLoop():nullptr;
    // Executed under the captured WL, so an enable/binding change cannot race
    // this observation and the following original gate.runAction. A disabled
    // still-bound gate must never be waited on from a client teardown thread.
    if (!gate || !loop || !loop->inGate() || (bound && bound!=loop) ||
        (bound && !gate->isEnabled()) || !enter(scope)) {
        retireOwnProvider(lease);return kIOReturnNotReady;
    }
    originalReset(client);
    leave(scope);
    if (!field(client,0xf0)) {
        __atomic_add_fetch(&completeCount,1U,__ATOMIC_RELAXED);
        if (!scope.consumed) __atomic_add_fetch(&noCallbackCount,1U,__ATOMIC_RELAXED);
    } else retireOwnProvider(lease);
    return kIOReturnSuccess;
}
uintptr_t resolveKernelSymbol(KernelPatcher &patcher,const char *name) {
    if (!name) return 0;
    patcher.clearError();
    const auto target=patcher.solveSymbol(KernelPatcher::KernelID,name);
    const bool valid=target && patcher.getError()==KernelPatcher::Error::NoError;
    patcher.clearError();
    return valid?static_cast<uintptr_t>(target):0;
}
bool addSignedAddress(uintptr_t base,intptr_t addend,uintptr_t &target) {
    if (addend>=0) {
        const uintptr_t amount=static_cast<uintptr_t>(addend);
        if (base>UINTPTR_MAX-amount) return false;
        target=base+amount;
    } else {
        const uintptr_t amount=static_cast<uintptr_t>(-(addend+1))+1U;
        if (base<amount) return false;
        target=base-amount;
    }
    return true;
}
int resolveRunActionRelocations(KernelPatcher &patcher,const uint8_t *bytes,uintptr_t base,
                                KernelContracts::Relocation *out) {
    if (!bytes || !base || !out) return EINVAL;
    for (size_t i=0;i<KernelContracts::RunActionRelocationCount;++i) {
        const auto &spec=KernelContracts::RunActionRelocationSpecs[i];
        uintptr_t target=0;
        if (spec.symbol) {
            uintptr_t symbol=resolveKernelSymbol(patcher,spec.symbol);
            if (!symbol && spec.alias) symbol=resolveKernelSymbol(patcher,spec.alias);
            if (!symbol || !addSignedAddress(symbol,spec.addend,target)) return EOPNOTSUPP;
        } else {
            const auto status=KernelContracts::relativeTargetAt(bytes,KernelContracts::RunActionContractBytes,
                                                                 base,spec,target);
            if (status!=KernelContracts::Status::Passed) return EOPNOTSUPP;
        }
        const int32_t range=spec.kind==KernelContracts::RelocationKind::RelativeCall ?
            ScanKernelIdentity::verifyRunningKernelCodeRange(target,1) :
            ScanKernelIdentity::verifyRunningKernelReadableRange(target,1);
        if (range) return range;
        out[i]={spec.instructionOffset,spec.displacementOffset,spec.instructionEndOffset,target,spec.kind};
    }
    return 0;
}
void wrappedReset(IOUserClient *client) {
    if (!__atomic_load_n(&enabled,__ATOMIC_ACQUIRE)) {originalReset(client);return;}
    NativeControlBridge::markClientClosing(client);
    ClientHandle handle;
    if (registry->beginClose(client,handle)!=ClientStatus::Passed) {originalReset(client);return;}
    ClientWorkLease lease;
    if (registry->acquireClosing(client,lease)!=ClientStatus::Passed) return;
    if (ml_at_interrupt_context() || !ml_get_interrupts_enabled()) {
        if (!field(client,0xf8)) retireOwnProvider(lease);
        return;
    }
    // Strong captured references keep both objects alive, including after the
    // controller clears its derived work-loop field during stop. No worker is
    // waited on and no registry lock is held across this synchronous action.
    const auto result=lease.workLoop()->runAction(resetAction,lease.controller(),&lease);
    if (result!=kIOReturnSuccess && !field(client,0xf8)) retireOwnProvider(lease);
    NativeControlBridge::collectClient(client);
}
} // namespace
bool ready() {return __atomic_load_n(&enabled,__ATOMIC_ACQUIRE);}
uint32_t completed() {return __atomic_load_n(&completeCount,__ATOMIC_RELAXED);}
uint32_t closedWithoutCallback() {return __atomic_load_n(&noCallbackCount,__ATOMIC_RELAXED);}
uint32_t retired() {return __atomic_load_n(&retiredCount,__ATOMIC_RELAXED);}
void resetFailedStart(IOUserClient *client) {if (ready()) wrappedReset(client);}
bool install(KernelPatcher &patcher,ClientRegistry &clients,size_t index,
             mach_vm_address_t base,size_t size) {
    if (attempted) return ready();attempted=true;
    if (!image(base,size)) return false;
    patcher.clearError();
    auto reset=patcher.solveSymbol(index,ResetSymbol,base,size);
    auto gated=patcher.solveSymbol(index,GatedSymbol,base,size);
    auto run=patcher.solveSymbol(KernelPatcher::KernelID,RunSymbol);
    if (patcher.getError()!=KernelPatcher::Error::NoError || reset!=base+0xa652c ||
        gated!=base+0xb4974 || !run ||
        memcmp(reinterpret_cast<void *>(reset),ResetPrefix,sizeof(ResetPrefix)) ||
        memcmp(reinterpret_cast<void *>(gated),GatedBody,sizeof(GatedBody))) {
        patcher.clearError();return false;
    }
    if (ScanKernelIdentity::verifyRunningKernelCodeRange(run,KernelContracts::RunActionContractBytes))
        return false;
    KernelContracts::Relocation relocations[KernelContracts::RunActionRelocationCount] {};
    const auto relocationStatus=resolveRunActionRelocations(patcher,
        reinterpret_cast<const uint8_t *>(run),run,relocations);
    if (relocationStatus) {patcher.clearError();return false;}
    KernelContracts::RunActionPlan contract;
    const auto contractStatus=KernelContracts::validateRunActionCurrent(
        reinterpret_cast<const uint8_t *>(run),KernelContracts::RunActionContractBytes,
        run,relocations,KernelContracts::RunActionRelocationCount,contract);
    if (contractStatus!=KernelContracts::Status::Passed) {patcher.clearError();return false;}
    scopeLock=IOSimpleLockAlloc();if (!scopeLock) return false;
    registry=&clients;actionReturn=contract.actionReturnPC;
    airport_awdl_original_gated_tail=gated+14;
    // No original trampoline is requested for the branch-containing gated
    // prefix. The validated PIC bridge above preserves its original behavior.
    KernelPatcher::RouteRequest gatedRoute(GatedSymbol,wrappedGated);
    if (!patcher.routeMultipleLong(index,&gatedRoute,1,base,size)) {patcher.clearError();return false;}
    KernelPatcher::RouteRequest resetRoute(ResetSymbol,wrappedReset,originalReset);
    if (!patcher.routeMultipleLong(index,&resetRoute,1,base,size) || !originalReset) {
        patcher.clearError();return false;
    }
    __atomic_store_n(&enabled,true,__ATOMIC_RELEASE);return true;
}
} }
