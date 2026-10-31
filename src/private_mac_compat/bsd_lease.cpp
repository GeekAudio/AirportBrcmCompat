#include "bsd_lease.hpp"
#include "../scan_kernel/ifnet_profiles.hpp"
#include "../scan_kernel/primary_interface_iokit.hpp"
#include <kern/thread.h>
#include <string.h>
#include <sys/errno.h>

namespace PrivateMAC { namespace BSDLease {
namespace {
// There is one registry for this pinned kernel/plugin generation. It never
// owns the stack scopes or extends the kernel's original callback lifetime.
CallbackPin *configured=nullptr;
Scope *head=nullptr;
RootScope *rootHead=nullptr;
CallbackScope *callbackHead=nullptr;
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
    if (configured || registry || returnPC || runtimeBuild || publicKPI) return EBUSY;
    if (!build || !KernelContracts::IfnetProfiles::knownPlan(contract)) return EINVAL;
    registry=IOLockAlloc();if (!registry) return ENOMEM;
    runtimeBuild=build;returnPC=contract.callbackReturnPC;publicKPI=false;
    // Startup-only publication, before a wrapper can create scopes.
    configured=this;return 0;
}
int CallbackPin::preparePublicKPI(int (*build)()) {
    if (configured || registry || returnPC || runtimeBuild || publicKPI) return EBUSY;
    if (!build) return EINVAL;
    registry=IOLockAlloc();if (!registry) return ENOMEM;
    runtimeBuild=build;publicKPI=true;
    // The caller must already have admitted the complete fixed callback
    // contract. This mode itself only installs the synchronization registry.
    configured=this;return 0;
}
int Scope::enter(CallbackPin &p,uintptr_t caller,IOService *c,IOService *i,ifnet_t ifp) {
    if (pin || owner || generation) return EBUSY;
    if (configured!=&p || !p.registry || p.publicKPI || !p.returnPC || !p.runtimeBuild) return ENXIO;
    if (registryOwner()==thread()) return EDEADLK;
    if (caller!=p.returnPC || p.runtimeBuild()) return EOPNOTSUPP;
    if (!c || !i || !ifp || !exactClass(c,"AirPort_BrcmNIC") ||
        !exactClass(i,"AirPort_BrcmNIC_Interface") || c->isInactive() || i->isInactive() ||
        i->getProvider()!=c) return ENXIO;
    // This ifp came from the original kernel callback at the verified callsite;
    // the kernel's I/O count, not this raw pointer or a normal ref, protects it.
    if (ifnet_softc(ifp)!=i ||
        !PrimaryInterface::propertyMatchesIfnet(i,ifnet_name(ifp),ifnet_unit(ifp))) return ENXIO;
    const uintptr_t current=thread();if (!current) return EINVAL;
    lock(p.registry);
    for (auto *s=head;s;s=s->next) if (s->owner==current) {unlock(p.registry);return EBUSY;}
    if (serial==UINT64_MAX) {unlock(p.registry);return EOVERFLOW;}
    pin=&p;controller=c;primary=i;borrowed=ifp;owner=current;generation=++serial;
    publicKPI=false;
    next=head;head=this;unlock(p.registry);return 0;
}
int RootScope::enter(CallbackPin &p,ifnet_t ifp,uintptr_t protocol,
                     uintptr_t command,void *data) {
    if (configured!=&p || !p.registry || !p.publicKPI || !p.runtimeBuild) return ENXIO;
    const uintptr_t current=thread();if (!current) return EINVAL;
    if (registryOwner()==current) return EDEADLK;
    const IfnetScopeCore::Tuple tuple(reinterpret_cast<uintptr_t>(ifp),protocol,
                                      command,reinterpret_cast<uintptr_t>(data));
    if (pin_ || owner_ || ticket_.active()) {
        if (pin_==&p && owner_==current) {
            lock(p.registry);
            p.scopeCore.beginRoot(current,tuple,ticket_); // Revoke reentry.
            unlock(p.registry);
            return EDEADLK;
        }
        return EBUSY;
    }
    lock(p.registry);
    const bool admitted=p.scopeCore.beginRoot(current,tuple,ticket_);
    if (!admitted) {unlock(p.registry);return EDEADLK;}
    pin_=&p;owner_=current;tuple_=tuple;next_=rootHead;rootHead=this;
    unlock(p.registry);
    if (p.runtimeBuild()) {leave();return EOPNOTSUPP;}
    return 0;
}
RootScope::~RootScope() {
    leave();
}
void RootScope::leave() {
    if (!pin_) return;
    CallbackPin *p=pin_;
    lock(p->registry);
    p->scopeCore.endRoot(thread(),ticket_);
    for (auto **root=&rootHead;*root;root=&(*root)->next_)
        if (*root==this) {*root=next_;break;}
    unlock(p->registry);
    pin_=nullptr;owner_=0;tuple_=IfnetScopeCore::Tuple();next_=nullptr;
}
int CallbackScope::enter(CallbackPin &p,ifnet_t ifp,uintptr_t command,
                         void *data) {
    if (configured!=&p || !p.registry || !p.publicKPI || !p.runtimeBuild) return ENXIO;
    const uintptr_t current=thread();if (!current) return EINVAL;
    if (registryOwner()==current) return EDEADLK;
    lock(p.registry);
    RootScope *root=nullptr;
    for (auto *candidate=rootHead;candidate;candidate=candidate->next_)
        if (candidate->pin_==&p && candidate->owner_==current) {root=candidate;break;}
    if (!root) {unlock(p.registry);return EOPNOTSUPP;}
    const IfnetScopeCore::Tuple tuple(reinterpret_cast<uintptr_t>(ifp),
                                      root->tuple_.protocol,command,
                                      reinterpret_cast<uintptr_t>(data));
    if ((pin_ || owner_ || ticket_.active()) &&
        !(pin_==&p && owner_==current)) {
        unlock(p.registry);return EBUSY;
    }
    if (!p.scopeCore.beginCallback(root->ticket_,current,tuple,ticket_)) {
        unlock(p.registry);return EOPNOTSUPP;
    }
    pin_=&p;owner_=current;tuple_=tuple;next_=callbackHead;callbackHead=this;
    unlock(p.registry);
    if (p.runtimeBuild()) {leave();return EOPNOTSUPP;}
    return 0;
}
CallbackScope::~CallbackScope() {
    leave();
}
void CallbackScope::leave() {
    if (!pin_) return;
    CallbackPin *p=pin_;
    lock(p->registry);
    p->scopeCore.endCallback(thread(),ticket_);
    for (auto **callback=&callbackHead;*callback;callback=&(*callback)->next_)
        if (*callback==this) {*callback=next_;break;}
    unlock(p->registry);
    pin_=nullptr;owner_=0;tuple_=IfnetScopeCore::Tuple();next_=nullptr;
}
int Scope::enterScoped(CallbackPin &p,IOService *c,IOService *i,ifnet_t ifp,
                       uintptr_t command,void *data) {
    if (configured!=&p || !p.registry || !p.publicKPI || !p.runtimeBuild) return ENXIO;
    const uintptr_t current=thread();if (!current) return EINVAL;
    if (registryOwner()==current) return EDEADLK;

    CallbackScope *callback=nullptr;
    lock(p.registry);
    for (auto *candidate=callbackHead;candidate;candidate=candidate->next_)
        if (candidate->pin_==&p && candidate->owner_==current) {
            callback=candidate;break;
        }
    if (!callback) {unlock(p.registry);return EOPNOTSUPP;}
    const IfnetScopeCore::Tuple request(reinterpret_cast<uintptr_t>(ifp),
                                        callback->tuple_.protocol,command,
                                        reinterpret_cast<uintptr_t>(data));
    if ((pin || owner || generation || performTicket.active()) &&
        !(pin==&p && owner==current && publicKPI)) {
        unlock(p.registry);return EBUSY;
    }
    if (!p.scopeCore.claimPerform(callback->ticket_,current,request,performTicket)) {
        unlock(p.registry);return EOPNOTSUPP;
    }
    unlock(p.registry);

    if (p.runtimeBuild()) {
        lock(p.registry);
        p.scopeCore.endPerform(current,performTicket);
        unlock(p.registry);
        return EOPNOTSUPP;
    }

    // The opaque perform tuple has been claimed before any driver/interface
    // identity checks. None of these checks run while the registry lock is held.
    if (!c || !i || !ifp || !exactClass(c,"AirPort_BrcmNIC") ||
        !exactClass(i,"AirPort_BrcmNIC_Interface") || c->isInactive() ||
        i->isInactive() || i->getProvider()!=c || ifnet_softc(ifp)!=i ||
        !PrimaryInterface::propertyMatchesIfnet(i,ifnet_name(ifp),ifnet_unit(ifp))) {
        lock(p.registry);
        p.scopeCore.endPerform(current,performTicket);
        unlock(p.registry);
        return ENXIO;
    }

    lock(p.registry);
    bool callbackStillActive=false;
    for (auto *candidate=callbackHead;candidate;candidate=candidate->next_)
        if (candidate==callback && candidate->pin_==&p &&
            candidate->owner_==current) {callbackStillActive=true;break;}
    if (!callbackStillActive || !p.scopeCore.held(performTicket,current,request)) {
        p.scopeCore.endPerform(current,performTicket);
        unlock(p.registry);return EOPNOTSUPP;
    }
    if (serial==UINT64_MAX) {
        p.scopeCore.endPerform(current,performTicket);
        unlock(p.registry);return EOVERFLOW;
    }
    pin=&p;controller=c;primary=i;borrowed=ifp;owner=current;generation=++serial;
    publicKPI=true;tuple=request;
    next=head;head=this;unlock(p.registry);return 0;
}
Scope::~Scope() {
    if (!pin) return;
    // A stack-only Scope is removed synchronously before original BSD callback
    // returns. This does not decrement the kernel's borrowed I/O count.
    lock(pin->registry);
    if (publicKPI) pin->scopeCore.endPerform(thread(),performTicket);
    for (auto **s=&head;*s;s=&(*s)->next) if (*s==this) {*s=next;break;}
    unlock(pin->registry);
    pin=nullptr;controller=nullptr;primary=nullptr;borrowed=nullptr;
    owner=0;generation=0;publicKPI=false;tuple=IfnetScopeCore::Tuple();next=nullptr;
}
bool held(IOService *c,IOService *i,ifnet_t expected,uint64_t *out) {
    if (out) *out=0;
    CallbackPin *p=configured;
    if (!p || !p->registry || !p->runtimeBuild || p->runtimeBuild() || !c || !i) return false;
    const uintptr_t current=thread();bool match=false;
    if (registryOwner()==current) return false; // Refuse before the nonrecursive lock.
    lock(p->registry);
    for (auto *s=head;s;s=s->next) if (s->owner==current && s->pin==p) {
        const bool identity=s->controller==c && s->primary==i && s->borrowed &&
                            (!expected || s->borrowed==expected) && s->generation;
        if (s->publicKPI) {
            if (identity && p->publicKPI) {
                match=p->scopeCore.held(s->performTicket,current,s->tuple);
            } else {
                // A mismatched identity is an invalid use of this one-shot
                // scope. Present a guaranteed-different opaque tuple so the
                // core revokes it before any later held() can authorize.
                IfnetScopeCore::Tuple mismatch=s->tuple;
                if (expected && s->borrowed!=expected)
                    mismatch.ifp=reinterpret_cast<uintptr_t>(expected);
                else mismatch.data^=uintptr_t(1);
                p->scopeCore.held(s->performTicket,current,mismatch);
            }
        } else match=identity;
        if (match && out) *out=s->generation;
        break;
    }
    unlock(p->registry);return match;
}
} } // namespace PrivateMAC::BSDLease
