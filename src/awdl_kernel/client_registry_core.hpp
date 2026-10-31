// Bounded state machine only. No authorization, object references or lock mock.
// Every operation requires the real adapter's one external serial lock.
#ifndef AIRPORT_AWDL_CLIENT_REGISTRY_CORE_HPP
#define AIRPORT_AWDL_CLIENT_REGISTRY_CORE_HPP
#include <stddef.h>
#include <stdint.h>

namespace AWDLKernel {
enum class ClientStatus : uint32_t {
    Passed=0, NotPrepared, Argument, Context, Object, BackendRejected,
    Duplicate, Capacity, Overflow, Missing, Stale, Closing, Busy, Pending
};
struct ClientHandle { uintptr_t client=0; uint64_t generation=0; };
struct ClientPointers {
    uintptr_t client=0,task=0,controller=0,provider=0,gate=0,loop=0;
};
struct ClientSnapshot {
    ClientHandle handle {};
    ClientPointers objects {};
};
class ClientRegistryCore {
    struct Slot {
        ClientPointers objects {};
        uint64_t generation=0;
        uint32_t inflight=0;
        bool closing=false,finishing=false,pending=false;
    };
    static constexpr size_t Slots=8;
    Slot slots[Slots] {};
    uint64_t serial=0;
    Slot *find(uintptr_t client) {
        for (auto &slot:slots) if (slot.objects.client==client && client) return &slot;
        return nullptr;
    }
    static ClientSnapshot snapshot(const Slot &s) {
        return {{s.objects.client,s.generation},s.objects};
    }
public:
    explicit ClientRegistryCore(uint64_t initialSerial=0):serial(initialSerial) {}
    ClientStatus admission(uintptr_t provider) const {
        if (!provider) return ClientStatus::Argument;
        bool vacant=false;
        for (const auto &s:slots) {
            if (s.objects.client && s.objects.provider==provider) return ClientStatus::Duplicate;
            if (!s.objects.client) vacant=true;
        }
        if (!vacant) return ClientStatus::Capacity;
        return serial==UINT64_MAX?ClientStatus::Overflow:ClientStatus::Passed;
    }
    ClientStatus add(const ClientPointers &objects,ClientHandle &out,bool pending=false) {
        out={};
        if (!objects.client || !objects.task || !objects.controller || !objects.provider ||
            !objects.gate || !objects.loop)
            return ClientStatus::Argument;
        Slot *vacant=nullptr;
        for (auto &slot:slots) {
            if (slot.objects.client==objects.client || slot.objects.provider==objects.provider)
                return ClientStatus::Duplicate;
            if (!slot.objects.client && !vacant) vacant=&slot;
        }
        if (!vacant) return ClientStatus::Capacity;
        if (serial==UINT64_MAX) return ClientStatus::Overflow;
        vacant->objects=objects;vacant->generation=++serial;
        vacant->inflight=0;vacant->closing=false;vacant->finishing=false;vacant->pending=pending;
        out={objects.client,vacant->generation};return ClientStatus::Passed;
    }
    ClientStatus acquire(uintptr_t client,ClientSnapshot &out) {
        out={};Slot *s=find(client);if (!s) return ClientStatus::Missing;
        if (s->closing) return ClientStatus::Closing;
        if (s->pending) return ClientStatus::Pending;
        if (s->inflight==UINT32_MAX) return ClientStatus::Overflow;
        ++s->inflight;out=snapshot(*s);return ClientStatus::Passed;
    }
    ClientStatus activate(const ClientHandle &handle) {
        Slot *s=find(handle.client);if (!s) return ClientStatus::Missing;
        if (!handle.generation || s->generation!=handle.generation) return ClientStatus::Stale;
        if (s->closing || s->finishing) return ClientStatus::Closing;
        if (!s->pending) return ClientStatus::Duplicate;
        s->pending=false;return ClientStatus::Passed;
    }
    // Lifecycle hooks only: registration already authorized this real client.
    // This grants lifetime, never permission for an external driver command.
    ClientStatus acquireClosing(uintptr_t client,ClientSnapshot &out) {
        out={};Slot *s=find(client);if (!s) return ClientStatus::Missing;
        if (s->finishing) return ClientStatus::Busy;
        if (s->inflight==UINT32_MAX) return ClientStatus::Overflow;
        ++s->inflight;out=snapshot(*s);return ClientStatus::Passed;
    }
    ClientStatus release(const ClientHandle &handle) {
        Slot *s=find(handle.client);if (!s) return ClientStatus::Missing;
        if (!handle.generation || s->generation!=handle.generation) return ClientStatus::Stale;
        if (!s->inflight) return ClientStatus::Stale;
        --s->inflight;return ClientStatus::Passed;
    }
    ClientStatus beginClose(uintptr_t client,ClientHandle &out) {
        out={};Slot *s=find(client);if (!s) return ClientStatus::Missing;
        s->closing=true;out={client,s->generation};return ClientStatus::Passed;
    }
    ClientStatus beginCloseProvider(uintptr_t provider,ClientHandle &out) {
        out={};if (!provider) return ClientStatus::Argument;
        for (auto &s:slots) if (s.objects.client && s.objects.provider==provider) {
            s.closing=true;out={s.objects.client,s.generation};return ClientStatus::Passed;
        }
        return ClientStatus::Missing;
    }
    size_t beginCloseController(uintptr_t controller) {
        if (!controller) return 0;
        size_t count=0;
        for (auto &s:slots) if (s.objects.client && s.objects.controller==controller) {
            s.closing=true;++count;
        }
        return count;
    }
    // Reserve removal while the adapter checks the actual retained WorkLoop
    // outside its spin lock. This reservation itself keeps every owner ref.
    ClientStatus startFinish(const ClientHandle &handle,ClientSnapshot &out) {
        out={};Slot *s=find(handle.client);if (!s) return ClientStatus::Missing;
        if (!handle.generation || s->generation!=handle.generation) return ClientStatus::Stale;
        if (!s->closing) return ClientStatus::Argument;
        if (s->inflight || s->finishing) return ClientStatus::Busy;
        s->finishing=true;out=snapshot(*s);return ClientStatus::Passed;
    }
    ClientStatus cancelFinish(const ClientHandle &handle) {
        Slot *s=find(handle.client);if (!s) return ClientStatus::Missing;
        if (!handle.generation || s->generation!=handle.generation) return ClientStatus::Stale;
        if (!s->finishing) return ClientStatus::Argument;
        s->finishing=false;return ClientStatus::Passed;
    }
    ClientStatus completeFinish(const ClientHandle &handle,ClientPointers &out) {
        out={};Slot *s=find(handle.client);if (!s) return ClientStatus::Missing;
        if (!handle.generation || s->generation!=handle.generation) return ClientStatus::Stale;
        if (!s->closing || !s->finishing || s->inflight) return ClientStatus::Busy;
        out=s->objects;*s=Slot{};return ClientStatus::Passed;
    }
};
} // namespace AWDLKernel
#endif
