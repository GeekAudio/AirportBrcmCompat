// Strict SET20 payload narrowing for the pre-12 IO80211ElCap request handler.
// The public wrapper zeroes a 0x1d0-byte local object and copies at most that
// much user data before dispatching request type 20 to the Brcm driver.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_ASSOCIATION_BRIDGE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_ASSOCIATION_BRIDGE_HPP

#include "../scan_kernel/association_compat.hpp"

namespace LegacyWiFi {
namespace AssociationBridge {

constexpr size_t MaximumPayloadSize = 0x1d0;
constexpr size_t ProjectedPayloadSize = AssociationCompat::LegacySize;
constexpr size_t NativePayloadSize = AssociationCompat::NativeSize;
constexpr size_t StorageSize = NativePayloadSize + MaximumPayloadSize;

using Result = AssociationCompat::Result;

inline bool overlap(const void *a, size_t an, const void *b, size_t bn) {
    const auto x = reinterpret_cast<uintptr_t>(a);
    const auto y = reinterpret_cast<uintptr_t>(b);
    return x <= y ? y - x < an : x - y < bn;
}

// Reuse this project's own native-to-Ventura codec, then accept only cases
// whose projected bytes beyond ElCap's exact 464-byte copy limit are zero.
// This avoids dropping flags, auth policy, PMK extensions, or unknown fields.
// Current userland requests that need any such extension are rejected until a
// separately proven legacy semantic mapping exists.
inline Result convert(const uint8_t *native, size_t nativeSize,
                      uint8_t *legacy, size_t legacySize) {
    if (!native || !legacy || nativeSize != NativePayloadSize ||
        legacySize != MaximumPayloadSize || overlap(native, nativeSize, legacy, legacySize))
        return {EINVAL, 0};
    uint8_t projected[ProjectedPayloadSize] {};
    const Result result = AssociationCompat::convert(native, nativeSize,
                                                       projected, sizeof(projected));
    if (result.error) {
        memset(projected, 0, sizeof(projected));
        return result;
    }
    for (size_t offset = MaximumPayloadSize; offset < sizeof(projected); ++offset) {
        if (projected[offset]) {
            memset(projected, 0, sizeof(projected));
            // AssociationCompat maps the native buffer +4 bytes after its
            // initial header fixups; report the matching native field offset.
            return {EOPNOTSUPP, static_cast<uint32_t>(offset + 4)};
        }
    }
    memcpy(legacy, projected, MaximumPayloadSize);
    memset(projected, 0, sizeof(projected));
    return {0, 0};
}

struct Scope {
    uintptr_t thread = 0, caller = 0;
    void *controller = nullptr;
    uint64_t source = 0;
    const uint8_t *legacy = nullptr;
    bool consumed = false;
    Scope *next = nullptr;
    Scope() = default;
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
};

struct Lock {
    void *value = nullptr;
    void (*enter)(void *) = nullptr;
    void (*leave)(void *) = nullptr;
};

struct Registry {
    Lock lock {};
    Scope *head = nullptr;

    bool add(Scope &scope) {
        if (!scope.thread || !scope.caller || !scope.controller || !scope.source ||
            !scope.legacy || !lock.value || !lock.enter || !lock.leave) return false;
        lock.enter(lock.value);
        for (auto *p = head; p; p = p->next) {
            if (p->thread == scope.thread) {
                lock.leave(lock.value);
                return false;
            }
        }
        scope.consumed = false;
        scope.next = head;
        head = &scope;
        lock.leave(lock.value);
        return true;
    }

    void remove(Scope &scope) {
        lock.enter(lock.value);
        for (auto **p = &head; *p; p = &(*p)->next) {
            if (*p == &scope) {
                *p = scope.next;
                break;
            }
        }
        scope.next = nullptr;
        lock.leave(lock.value);
    }

    // -1 denotes an unrelated copyIn. A matching thread/caller with any
    // different argument, or a second consume, is a hard error.
    int consume(uintptr_t thread, uintptr_t caller, void *controller,
                uint64_t source, void *destination, size_t size) {
        if (!lock.value || !lock.enter || !lock.leave) return -1;
        lock.enter(lock.value);
        for (auto *p = head; p; p = p->next) {
            if (p->thread != thread || p->caller != caller) continue;
            int error = EINVAL;
            if (!p->consumed && p->controller == controller && p->source == source &&
                size == MaximumPayloadSize && destination &&
                !overlap(destination, size, p->legacy, MaximumPayloadSize)) {
                memcpy(destination, p->legacy, MaximumPayloadSize);
                p->consumed = true;
                error = 0;
            }
            lock.leave(lock.value);
            return error;
        }
        lock.leave(lock.value);
        return -1;
    }
};

using Original = int (*)(void *, void *, void *, ScanCompat::Request *, bool);
using CopyIn = int (*)(void *, uint64_t, void *, size_t);

struct API {
    Original original = nullptr;
    CopyIn copyIn = nullptr;
    void *(*allocate)(size_t) = nullptr;
    void (*deallocate)(void *, size_t) = nullptr;
    uintptr_t (*currentThread)() = nullptr;
    Registry *registry = nullptr;
    uintptr_t copyInCaller = 0;
};

inline bool eligible(const ScanCompat::Request *request, void *controller,
                     void *interface, void *virtualInterface, bool user64) {
    return request && controller && interface && !virtualInterface && user64 &&
        request->type == 20 && request->value == 0 &&
        request->length == NativePayloadSize && request->userData;
}

struct Buffer {
    API &api;
    uint8_t *bytes;
    explicit Buffer(API &value)
        : api(value), bytes(static_cast<uint8_t *>(value.allocate(StorageSize))) {}
    ~Buffer() {
        if (bytes) {
            memset(bytes, 0, StorageSize);
            api.deallocate(bytes, StorageSize);
        }
    }
    Buffer(const Buffer &) = delete;
    Buffer &operator=(const Buffer &) = delete;
};

struct RequestLength {
    ScanCompat::Request &request;
    uint32_t saved;
    explicit RequestLength(ScanCompat::Request &value)
        : request(value), saved(value.length) { request.length = MaximumPayloadSize; }
    ~RequestLength() { request.length = saved; }
    RequestLength(const RequestLength &) = delete;
    RequestLength &operator=(const RequestLength &) = delete;
};

inline int handle(API &api, void *controller, void *interface, void *virtualInterface,
                  ScanCompat::Request *request, bool user64,
                  Result *validation = nullptr, bool *consumed = nullptr) {
    if (validation) *validation = {-1, 0};
    if (consumed) *consumed = false;
    if (!eligible(request, controller, interface, virtualInterface, user64))
        return api.original(controller, interface, virtualInterface, request, user64);

    Buffer buffer(api);
    if (!buffer.bytes) return ENOMEM;
    int error = api.copyIn(controller, request->userData, buffer.bytes, NativePayloadSize);
    if (error) return error;
    const Result result = convert(buffer.bytes, NativePayloadSize,
                                  buffer.bytes + NativePayloadSize, MaximumPayloadSize);
    if (validation) *validation = result;
    if (result.error) return result.error;

    Scope scope;
    scope.thread = api.currentThread();
    scope.caller = api.copyInCaller;
    scope.controller = controller;
    scope.source = request->userData;
    scope.legacy = buffer.bytes + NativePayloadSize;
    if (!api.registry || !api.registry->add(scope)) return EBUSY;
    {
        // ElCap copies min(req_len, 0x1d0) from userspace in this handler.
        // Pin it to exactly the encoded payload length for our one-shot copyIn.
        RequestLength length(*request);
        error = api.original(controller, interface, virtualInterface, request, user64);
    }
    api.registry->remove(scope);
    if (consumed) *consumed = scope.consumed;
    if (!error && !scope.consumed) return EIO;
    return error;
}

inline int consumeCopyIn(API &api, uintptr_t thread, uintptr_t caller,
                         void *controller, uint64_t source,
                         void *destination, size_t size) {
    if (!api.registry) return -1;
    return api.registry->consume(thread, caller, controller, source, destination, size);
}

} // namespace AssociationBridge
} // namespace LegacyWiFi

#endif
