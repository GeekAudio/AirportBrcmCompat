#include "driver_version_backend.hpp"
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <libkern/c++/OSBoolean.h>
#include <kern/task.h>
#include <mach-o/loader.h>

namespace AWDLKernel { namespace {
constexpr size_t HeaderBound=8192;
constexpr size_t VersionOffset=0x3d858,VersionEnd=0x3d8f2;
constexpr size_t RoleOffset=0xb0778,BSDNameOffset=0xb0872;
constexpr uint8_t BrcmUUID[16]={0xe4,0x67,0x8f,0xeb,0x1d,0xc1,0x35,0xcc,
    0x93,0x06,0x48,0x02,0x10,0x83,0xd0,0x4a};
constexpr uint8_t LegacyUUID[16]={0x4c,0x07,0x53,0x8b,0x62,0xeb,0x3d,0x6d,
    0xae,0xf9,0x93,0xbc,0xdc,0xf4,0x5f,0xab};
// Complete 35-byte instruction prefix, ending after the first movabs. No
// external GOT/call relocation. Leaf getters are checked in their entirety.
constexpr uint8_t VersionGuard[35]={0x48,0x85,0xd2,0x0f,0x84,0x8b,0,0,0,0x55,0x48,0x89,0xe5,
    0xc7,0x02,0x01,0,0,0,0x66,0xc7,0x42,0x04,0x3d,0,0x48,0xb8,0x42,0x72,0x6f,0x61,0x64,
    0x63,0x6f,0x6d};
constexpr uint8_t RoleGuard[]={0x55,0x48,0x89,0xe5,0x8b,0x87,0xc0,0,0,0,0x5d,0xc3};
constexpr uint8_t BSDNameGuard[]={0x55,0x48,0x89,0xe5,0x48,0x8d,0x87,0xd8,0,0,0,0x5d,0xc3};
bool range(size_t offset,size_t length,size_t bound) {
    return offset<=bound && length<=bound-offset;
}
bool name(const char field[16],const char *expected) {
    for (size_t j=0;j<16;++j) {
        if (field[j]!=expected[j]) return false;
        if (!expected[j]) {for (++j;j<16;++j) if (field[j]) return false;return true;}
    }
    return false;
}
VersionPinStatus image(const uint8_t *bytes,size_t size,const uint8_t uuid[16],
                       size_t codeStart,size_t codeEnd) {
    if (!bytes || reinterpret_cast<uintptr_t>(bytes)%alignof(mach_header_64) ||
        size<sizeof(mach_header_64) || reinterpret_cast<uintptr_t>(bytes)>UINTPTR_MAX-size)
        return VersionPinStatus::Input;
    const auto *h=reinterpret_cast<const mach_header_64 *>(bytes);
    if (h->magic!=MH_MAGIC_64 || h->cputype!=CPU_TYPE_X86_64 ||
        h->cpusubtype!=CPU_SUBTYPE_X86_64_ALL || h->filetype!=MH_KEXT_BUNDLE ||
        h->sizeofcmds>HeaderBound-sizeof(*h) || h->sizeofcmds>size-sizeof(*h) ||
        !h->ncmds || h->ncmds>h->sizeofcmds/sizeof(load_command)) return VersionPinStatus::MachO;
    size_t offset=sizeof(*h),end=offset+h->sizeofcmds;
    unsigned uuids=0,texts=0,sections=0;
    for (uint32_t j=0;j<h->ncmds;++j) {
        if (!range(offset,sizeof(load_command),end)) return VersionPinStatus::MachO;
        const auto *c=reinterpret_cast<const load_command *>(bytes+offset);
        if (c->cmdsize<sizeof(*c) || c->cmdsize%8 || !range(offset,c->cmdsize,end))
            return VersionPinStatus::MachO;
        if (c->cmd==LC_UUID) {
            if (c->cmdsize!=sizeof(uuid_command) || ++uuids!=1 ||
                memcmp(reinterpret_cast<const uuid_command *>(c)->uuid,uuid,16)) return VersionPinStatus::UUID;
        } else if (c->cmd==LC_SEGMENT_64) {
            if (c->cmdsize<sizeof(segment_command_64)) return VersionPinStatus::MachO;
            const auto *s=reinterpret_cast<const segment_command_64 *>(c);
            const size_t available=c->cmdsize-sizeof(*s);
            if (s->nsects>available/sizeof(section_64) || available!=s->nsects*sizeof(section_64))
                return VersionPinStatus::MachO;
            if (name(s->segname,"__TEXT")) {
                if (++texts!=1 || s->vmsize<codeEnd || s->vmsize>size ||
                    s->vmaddr>UINT64_MAX-s->vmsize ||
                    !(s->initprot&4) || !(s->maxprot&4)) return VersionPinStatus::Code;
                const auto *section=reinterpret_cast<const section_64 *>(s+1);
                for (uint32_t k=0;k<s->nsects;++k) if (name(section[k].sectname,"__text")) {
                    if (++sections!=1 || !name(section[k].segname,"__TEXT") ||
                        section[k].addr<s->vmaddr || section[k].addr-s->vmaddr!=codeStart ||
                        section[k].size!=codeEnd-codeStart ||
                        !range(codeStart,section[k].size,s->vmsize) ||
                        !(section[k].flags&S_ATTR_PURE_INSTRUCTIONS)) return VersionPinStatus::Code;
                }
            }
        }
        offset+=c->cmdsize;
    }
    if (offset!=end) return VersionPinStatus::MachO;
    if (uuids!=1) return VersionPinStatus::UUID;
    return texts==1 && sections==1?VersionPinStatus::Passed:VersionPinStatus::Code;
}
VersionPinStatus pins(const uint8_t *brcm,size_t bn,const uint8_t *legacy,size_t ln) {
    auto status=image(brcm,bn,BrcmUUID,0x990,0x349aa0);
    if (status!=VersionPinStatus::Passed) return status;
    status=image(legacy,ln,LegacyUUID,0xeb0,0xf5e56);
    if (status!=VersionPinStatus::Passed) return status;
    if (!range(VersionOffset,VersionEnd-VersionOffset,bn) ||
        !range(RoleOffset,sizeof(RoleGuard),ln) || !range(BSDNameOffset,sizeof(BSDNameGuard),ln))
        return VersionPinStatus::Code;
    if (memcmp(brcm+VersionOffset,VersionGuard,sizeof(VersionGuard)) ||
        memcmp(legacy+RoleOffset,RoleGuard,sizeof(RoleGuard)) ||
        memcmp(legacy+BSDNameOffset,BSDNameGuard,sizeof(BSDNameGuard))) return VersionPinStatus::Guard;
    return VersionPinStatus::Passed;
}
bool entitled(task_t task,const char *key) {
    OSObject *value=IOUserClient::copyClientEntitlement(task,key);
    const bool allowed=value==kOSBooleanTrue;
    if (value) value->release();
    return allowed;
}
bool exactClass(IOService *value,const char *expected) {
    return value && value->getMetaClass() && !strcmp(value->getMetaClass()->getClassName(),expected);
}
} // namespace

VersionPinStatus DriverVersionBackend::initialize(const void *b,size_t bn,const void *l,size_t ln) {
    brcm=nullptr;legacy=nullptr;brcmSize=legacySize=0;
    getVersion=nullptr;getRole=nullptr;getBSDName=nullptr;
    const auto *bb=static_cast<const uint8_t *>(b),*ll=static_cast<const uint8_t *>(l);
    const auto status=pins(bb,bn,ll,ln);
    if (status!=VersionPinStatus::Passed) return status;
    brcm=bb;legacy=ll;brcmSize=bn;legacySize=ln;
    getVersion=reinterpret_cast<GetVersion>(reinterpret_cast<uintptr_t>(bb)+VersionOffset);
    getRole=reinterpret_cast<GetRole>(reinterpret_cast<uintptr_t>(ll)+RoleOffset);
    getBSDName=reinterpret_cast<GetBSDName>(reinterpret_cast<uintptr_t>(ll)+BSDNameOffset);
    return VersionPinStatus::Passed;
}
bool DriverVersionBackend::validPins() const {
    return getVersion && getRole && getBSDName &&
        pins(brcm,brcmSize,legacy,legacySize)==VersionPinStatus::Passed;
}
bool DriverVersionBackend::identity(IOService *controller,IOService *provider) const {
    if (!exactClass(controller,"AirPort_BrcmNIC") ||
        !exactClass(provider,"AirPort_BrcmNIC_P2PInterface") ||
        controller->isInactive() || provider->isInactive() || provider->getProvider()!=controller)
        return false;
    IOWorkLoop *loop=controller->getWorkLoop();
    if (!loop || !loop->inGate() || provider->getWorkLoop()!=loop) return false;
    if (getRole(provider)!=6) return false;
    const char *bsd=getBSDName(provider);
    static const char expected[6]={'a','w','d','l','0',0};
    // Only the actual getter's six owned bytes, while its object is retained
    // and the same original controller gate excludes teardown. No softc guess.
    return bsd && !memcmp(bsd,expected,sizeof(expected));
}
bool DriverVersionBackend::matchesProviderIdentity(IOService *controller,IOService *provider) const {
    return validPins() && identity(controller,provider);
}
VersionResult DriverVersionBackend::get43(task_t task,IOService *controller,IOService *provider,
                                         const VersionCall &call) const {
    VersionResult result;
    if (!validVersionCall(call) ||
        versionRangesOverlap(this,sizeof(*this),call.output,call.outputCapacity)) return result;
    memset(call.output,0,call.outputCapacity);
    if (!validPins()) {result.status=VersionStatus::Unbound;return result;}
    if (task==TASK_NULL || task!=current_task()) {result.status=VersionStatus::TaskIdentity;return result;}
    if (!entitled(task,"com.apple.wlan.authentication") ||
        !entitled(task,"com.apple.wifi_awdl.event_monitor")) {
        result.status=VersionStatus::Entitlement;return result;
    }
    if (!identity(controller,provider)) {result.status=VersionStatus::ObjectIdentity;return result;}
    LegacyVersion scratch {};
    const int32_t raw=getVersion(controller,provider,&scratch);
    // A reference is not a lifetime lease. Keep the integration owner contract
    // and recheck actual topology/gate before exposing any backend bytes.
    if (task!=current_task() || !validPins() || !identity(controller,provider)) {
        result.status=VersionStatus::ObjectIdentity;result.backendCalled=true;
        result.rawBackendStatus=raw;return result;
    }
    return renderLegacyVersion(scratch,raw,call.output,call.outputCapacity);
}
} // namespace AWDLKernel
