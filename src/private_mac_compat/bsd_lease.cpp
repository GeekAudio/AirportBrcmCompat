#include "bsd_lease.hpp"
#include <kern/thread.h>
#include <string.h>
#include <sys/errno.h>

namespace PrivateMAC { namespace BSDLease {
namespace {
// There is one registry for this pinned kernel/plugin generation. It never
// owns the stack scopes or extends the kernel's original callback lifetime.
CallbackPin *configured=nullptr;
Scope *head=nullptr;
uint64_t serial=0;
uintptr_t lockOwner=0;
uintptr_t thread() { return reinterpret_cast<uintptr_t>(current_thread()); }
void lock(IOLock *value) {
    IOLockLock(value);__atomic_store_n(&lockOwner,thread(),__ATOMIC_RELEASE);
}
void unlock(IOLock *value) {
    __atomic_store_n(&lockOwner,uintptr_t(0),__ATOMIC_RELEASE);IOLockUnlock(value);
}
bool exactClass(const IOService *service,const char *name) {
    return service && service->getMetaClass() && !strcmp(service->getMetaClass()->getClassName(),name);
}
}
uintptr_t registryOwner() { return __atomic_load_n(&lockOwner,__ATOMIC_ACQUIRE); }
int CallbackPin::prepare(const KernelContracts::IfnetIoctlPlan &contract,
                         int (*build)()) {
    if (configured || registry || returnPC) return EBUSY;
    if (!build || contract.proofTag!=KernelContracts::IfnetPlanProof ||
        !contract.imageBase || contract.imageSpan!=KernelContracts::IfnetIoctlContractBytes ||
        contract.imageBase>UINTPTR_MAX-0x211 ||
        contract.callbackReturnPC!=contract.imageBase+0x211) return EINVAL;
    registry=IOLockAlloc();if (!registry) return ENOMEM;
    runtimeBuild=build;returnPC=contract.callbackReturnPC;
    // Startup-only publication, before a wrapper can create scopes.
    configured=this;return 0;
}
int Scope::enter(CallbackPin &p,uintptr_t caller,IOService *c,IOService *i,ifnet_t ifp) {
    if (pin || owner || generation) return EBUSY;
    if (configured!=&p || !p.registry || !p.returnPC || !p.runtimeBuild) return ENXIO;
    if (registryOwner()==thread()) return EDEADLK;
    if (caller!=p.returnPC || p.runtimeBuild()) return EOPNOTSUPP;
    if (!c || !i || !ifp || !exactClass(c,"AirPort_BrcmNIC") ||
        !exactClass(i,"AirPort_BrcmNIC_Interface") || c->isInactive() || i->isInactive() ||
        i->getProvider()!=c) return ENXIO;
    // This ifp came from the original kernel callback at the verified callsite;
    // the kernel's I/O count, not this raw pointer or a normal ref, protects it.
    if (ifnet_softc(ifp)!=i || ifnet_unit(ifp)!=1) return ENXIO;
    const char *name=ifnet_name(ifp);if (!name || strcmp(name,"en")) return ENXIO;
    const uintptr_t current=thread();if (!current) return EINVAL;
    lock(p.registry);
    for (auto *s=head;s;s=s->next) if (s->owner==current) {unlock(p.registry);return EBUSY;}
    if (serial==UINT64_MAX) {unlock(p.registry);return EOVERFLOW;}
    pin=&p;controller=c;primary=i;borrowed=ifp;owner=current;generation=++serial;
    next=head;head=this;unlock(p.registry);return 0;
}
Scope::~Scope() {
    if (!pin) return;
    // A stack-only Scope is removed synchronously before original BSD callback
    // returns. This does not decrement the kernel's borrowed I/O count.
    lock(pin->registry);
    for (auto **s=&head;*s;s=&(*s)->next) if (*s==this) {*s=next;break;}
    unlock(pin->registry);
    pin=nullptr;controller=nullptr;primary=nullptr;borrowed=nullptr;
    owner=0;generation=0;next=nullptr;
}
bool held(IOService *c,IOService *i,ifnet_t expected,uint64_t *out) {
    if (out) *out=0;
    CallbackPin *p=configured;
    if (!p || !p->registry || !p->runtimeBuild || p->runtimeBuild() || !c || !i) return false;
    const uintptr_t current=thread();bool match=false;
    if (registryOwner()==current) return false; // Refuse before the nonrecursive lock.
    lock(p->registry);
    for (auto *s=head;s;s=s->next) if (s->owner==current && s->controller==c && s->primary==i) {
        match=s->pin==p && s->borrowed && (!expected || s->borrowed==expected) && s->generation;
        if (match && out) *out=s->generation;
        break;
    }
    unlock(p->registry);return match;
}
} } // namespace PrivateMAC::BSDLease
