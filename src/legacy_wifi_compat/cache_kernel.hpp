// Lifecycle and allocation ownership for the fixed injected provider.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_CACHE_KERNEL_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_CACHE_KERNEL_HPP

#include <Headers/kern_patcher.hpp>
#include "cache_allocation_registry.hpp"
#include "selective_cache.hpp"

namespace LegacyWiFi { namespace CacheKernel {

using Source = NetworkIdentity::Source;
using OwnerKey = CacheAllocationRegistry::OwnerKey;
using Tuple = CacheAllocationRegistry::Tuple;
constexpr size_t MaximumPruneNodes = 1024;

struct API {
    // Called only immediately after the original manager initializer returns
    // true, while its caller still owns the live initialization arguments.
    // Must recognize already admitted exact child classes; no OS-version guess.
    Source (*classifyInitialization)(void *controller, void *interface) = nullptr;
    // Arguments are live on the admitted initializer path. Check the exact
    // manager/timer types, controller WorkLoop and timer attachment.
    bool (*validateInitialization)(void *manager, void *controller, void *interface,
                                   void *workLoop, void *timer) = nullptr;
    // Called with references held to all three objects. Must require the
    // current thread to own the same WorkLoop gate and the live primary binding.
    bool (*validateBinding)(void *manager, void *controller, void *interface,
                            void *workLoop, void *timer, Source) = nullptr;
    // retainObject must be a nonblocking base OSObject retain, with no override
    // or callback: manager acquisition uses it while the registry lock is held.
    // releaseObject is always called outside that lock and may run native free.
    void (*retainObject)(void *) = nullptr;
    void (*releaseObject)(void *) = nullptr;
    // The pinned init creates a passive timer. Synchronize with its captured
    // WorkLoop, disable and cancel it, then return with the gate released.
    // This must complete before the original interface detach is called.
    void (*quiesceTimer)(void *workLoop, void *timer) = nullptr;
};

// Caller must have verified the complete CacheProviderContract before routing
// any selected entry. Resident partial routes always preserve the native path.
bool initialize(KernelPatcher &, size_t providerIndex, uintptr_t providerBase,
                size_t providerSize, bool cacheContractVerified, const API &);
bool ready();

// The caller must already own live controller/interface arguments and keep the
// verified native gate continuously held for an operation. acquire() finds a
// keeper-backed manager before reading the interface's native manager slot.
// A lease preserves memory lifetime; it does not prevent detach revocation or
// independently authorize a cache write. current() must precede cache access.
class Lease {
public:
    Lease() = default;
    ~Lease();
    Lease(const Lease &) = delete;
    Lease &operator=(const Lease &) = delete;
    Lease(Lease &&) = delete;
    Lease &operator=(Lease &&) = delete;
    bool acquire(void *controller, void *interface, Source);
    bool current() const;
    void reset();
    const OwnerKey &key() const { return heldKey; }
    Source source() const { return heldSource; }
    void *manager() const { return reinterpret_cast<void *>(heldKey.manager); }
private:
    OwnerKey heldKey {};
    void *controller = nullptr;
    void *interface = nullptr;
    void *workLoop = nullptr;
    void *timer = nullptr;
    Source heldSource = Source::Unknown;
};

// Synchronously prune the current manager's scan cache for one owned network
// identity. The caller must hold the same controller WorkLoop gate from before
// this call until it returns. Scratch storage is caller-owned and bounded to
// the fixed provider maximum; this adapter performs no allocation and never
// releases the gate or calls a provider callback between validation and writes.
SelectiveCache::Status prune(Lease &, const NetworkMatch::Identity &,
                             SelectiveCache::Entry *scratch, size_t capacity,
                             SelectiveCache::Result *result);

// Allocation queries alone do not supply a lease or authorize cache writes.
bool owner(void *manager, void *controller, void *interface, Source, OwnerKey *);
bool ownsAllocations(const OwnerKey &, Source, const Tuple &);

} }
#endif
