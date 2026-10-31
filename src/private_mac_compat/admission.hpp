// Portable admission only. No provider retain, native stop exclusion or hooks.
#ifndef SKYWALK_PRIVATE_MAC_ADMISSION_HPP
#define SKYWALK_PRIVATE_MAC_ADMISSION_HPP
#include <stdint.h>
#include <stddef.h>
#include <sys/errno.h>

namespace PrivateMAC {
struct Binding {
    uintptr_t controller=0,primary=0;
    uint64_t generation=0;
};
class Admission;
class AdmissionLease {
    friend class Admission;
    const Admission *issuer=nullptr;
    Binding target {};
    uintptr_t owner=0;
    uint64_t ticket=0;
public:
    // Immutable once issued. Copies are stale-safe capabilities, not a new
    // acquisition; only their actual original owner thread may finish/poison.
    bool issued() const { return issuer!=nullptr; }
};
class Admission {
    static constexpr uint64_t Reserved=~uint64_t(0);
    const Binding target;
    alignas(8) uint64_t active=0;
    alignas(8) uint64_t serial=0; // Accessed only while active==Reserved.
    uintptr_t owner=0;           // Read/written only while active==Reserved.
    uint32_t quarantine=0,reason=0;
    static bool valid(const Binding &b) { return b.controller && b.primary && b.generation; }
    static bool same(const Binding &a,const Binding &b) {
        return a.controller==b.controller && a.primary==b.primary && a.generation==b.generation;
    }
    int claim(const AdmissionLease &lease,uintptr_t currentThread) {
        if (lease.issuer!=this || !lease.ticket || lease.ticket==Reserved || !same(lease.target,target))
            return EINVAL;
        if (!currentThread || currentThread!=lease.owner) return EPERM;
        uint64_t expected=lease.ticket;
        if (!__atomic_compare_exchange_n(&active,&expected,Reserved,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return ESTALE;
        if (owner!=currentThread) {
            __atomic_store_n(&active,lease.ticket,__ATOMIC_RELEASE);
            return EPERM;
        }
        return 0;
    }
    void markQuarantine(uint32_t why) {
        // Caller holds Reserved, so the first reason is single-writer.
        if (!__atomic_load_n(&quarantine,__ATOMIC_RELAXED)) {
            __atomic_store_n(&reason,why?why:1U,__ATOMIC_RELAXED);
            __atomic_store_n(&quarantine,1U,__ATOMIC_RELEASE);
        }
    }
public:
    static_assert(__atomic_always_lock_free(sizeof(uint64_t),nullptr),"Admission requires lock-free 64-bit CAS");
    explicit Admission(const Binding &binding):target(binding) {}
    Admission(const Admission &)=delete;
    Admission &operator=(const Admission &)=delete;
    // Every primary SET20 path, including legacy/nonprivate, must use this SAME
    // instance. This header does not wire a dispatcher or exclude native stop.
    // A live Admission must outlive all entrants, observers and lease copies.
    // Construct a new generation only after separately proved native drainage.
    bool isQuarantined() const { return __atomic_load_n(&quarantine,__ATOMIC_ACQUIRE)!=0; }
    uint32_t quarantineReason() const {
        if (!isQuarantined()) return 0;
        return __atomic_load_n(&reason,__ATOMIC_ACQUIRE);
    }
    // Observation only. A false value never authorizes entry: call enter().
    bool isBusy() const { return __atomic_load_n(&active,__ATOMIC_ACQUIRE)!=0; }
    // currentThread is the actual trusted calling thread identity, never an
    // ioctl payload value or deferred worker identity. Its lifetime must cover
    // the lease. out is fresh, caller-owned and published only after success.
    int enter(const Binding &binding,uintptr_t currentThread,AdmissionLease &out) {
        if (!valid(target) || !valid(binding) || !currentThread || out.issued()) return EINVAL;
        if (binding.controller!=target.controller || binding.primary!=target.primary) return ENXIO;
        if (binding.generation!=target.generation) return ESTALE;
        if (isQuarantined()) return EIO;
        uint64_t expected=0;
        if (!__atomic_compare_exchange_n(&active,&expected,Reserved,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
            return isQuarantined()?EIO:EBUSY;
        // Close a pre-CAS quarantine observation race; finish never clears it.
        if (isQuarantined()) {
            __atomic_store_n(&active,uint64_t(0),__ATOMIC_RELEASE);
            return EIO;
        }
        if (serial==Reserved-1) {
            markQuarantine(EOVERFLOW);
            __atomic_store_n(&active,uint64_t(0),__ATOMIC_RELEASE);
            return EOVERFLOW; // A ticket is never reused after wraparound.
        }
        const uint64_t ticket=++serial;
        owner=currentThread;
        out.target=target;out.owner=currentThread;out.ticket=ticket;out.issuer=this;
        __atomic_store_n(&active,ticket,__ATOMIC_RELEASE);
        return 0;
    }
    int poison(const AdmissionLease &lease,uintptr_t currentThread,uint32_t why) {
        const int error=claim(lease,currentThread);if (error) return error;
        markQuarantine(why);
        __atomic_store_n(&active,lease.ticket,__ATOMIC_RELEASE);
        return 0; // Lease remains held for owner cleanup; no factory fallback.
    }
    int finish(const AdmissionLease &lease,uintptr_t currentThread) {
        const int error=claim(lease,currentThread);if (error) return error;
        owner=0;
        __atomic_store_n(&active,uint64_t(0),__ATOMIC_RELEASE);
        return 0; // In particular, never resets quarantine or first reason.
    }
};
} // namespace PrivateMAC
#endif
