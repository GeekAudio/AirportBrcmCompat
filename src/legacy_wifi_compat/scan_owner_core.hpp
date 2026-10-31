// Host-testable per-thread owner-PID scopes for one guarded proc_selfpid call.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_SCAN_OWNER_CORE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_SCAN_OWNER_CORE_HPP

#include <stddef.h>
#include <stdint.h>

namespace LegacyWiFi {
namespace ScanOwner {
namespace Core {

constexpr size_t MaximumScopes = 16;

inline bool addRelative32(uintptr_t instructionEnd, int32_t displacement,
                          uintptr_t *target) {
    if (!target) return false;
    if (displacement >= 0) {
        const uintptr_t amount = static_cast<uint32_t>(displacement);
        if (instructionEnd > UINTPTR_MAX - amount) return false;
        *target = instructionEnd + amount;
        return true;
    }
    const uintptr_t amount = static_cast<uint32_t>(-
        static_cast<int64_t>(displacement));
    if (instructionEnd < amount) return false;
    *target = instructionEnd - amount;
    return true;
}

inline bool relative32(uintptr_t instructionEnd, uintptr_t target,
                       int32_t *displacement) {
    if (!displacement) return false;
    if (target >= instructionEnd) {
        const uintptr_t amount = target - instructionEnd;
        if (amount > static_cast<uintptr_t>(INT32_MAX)) return false;
        *displacement = static_cast<int32_t>(amount);
        return true;
    }
    const uintptr_t amount = instructionEnd - target;
    const uintptr_t negativeLimit = static_cast<uintptr_t>(INT32_MAX) + 1U;
    if (amount > negativeLimit) return false;
    if (amount == negativeLimit) *displacement = INT32_MIN;
    else *displacement = -static_cast<int32_t>(amount);
    return true;
}

struct Lock {
    void *value = nullptr;
    void (*enter)(void *) = nullptr;
    void (*leave)(void *) = nullptr;
};

struct Scope {
    uintptr_t thread = 0;
    void *process = nullptr;
    int pid = 0;
    Scope *next = nullptr;
    bool linked = false;
    Scope() = default;
    Scope(const Scope &) = delete;
    Scope &operator=(const Scope &) = delete;
};

class Registry {
public:
    Registry() = default;
    explicit Registry(const Lock &lock) : lock_(lock), ready_(true) {}
    Registry(const Registry &) = delete;
    Registry &operator=(const Registry &) = delete;

    bool prepare(const Lock &lock) {
        if (ready_ || !lock.value || !lock.enter || !lock.leave) return false;
        lock_ = lock;
        ready_ = true;
        return true;
    }

    bool ready() const {
        return ready_ && lock_.value && lock_.enter && lock_.leave;
    }

    bool enter(Scope &scope, uintptr_t thread, void *process, int pid) {
        if (!ready() || !thread || !process || pid <= 0 || scope.linked) return false;
        lock_.enter(lock_.value);
        if (count_ >= MaximumScopes) {
            lock_.leave(lock_.value);
            return false;
        }
        scope.thread = thread;
        scope.process = process;
        scope.pid = pid;
        scope.next = head_;
        scope.linked = true;
        head_ = &scope;
        ++count_;
        lock_.leave(lock_.value);
        return true;
    }

    bool leave(Scope &scope) {
        if (!ready()) return false;
        lock_.enter(lock_.value);
        bool removed = false;
        for (Scope **current = &head_; *current; current = &(*current)->next) {
            if (*current == &scope) {
                *current = scope.next;
                scope.thread = 0;
                scope.process = nullptr;
                scope.pid = 0;
                scope.next = nullptr;
                scope.linked = false;
                --count_;
                removed = true;
                break;
            }
        }
        lock_.leave(lock_.value);
        return removed;
    }

    // The hook is installed only at the provider's verified startScan callsite.
    // A different thread or absent scope keeps the original process identity.
    int pidForThread(uintptr_t thread, int originalPID) const {
        if (!ready() || !thread) return originalPID;
        lock_.enter(lock_.value);
        int pid = originalPID;
        for (Scope *scope = head_; scope; scope = scope->next) {
            if (scope->thread == thread) {
                pid = scope->pid;
                break;
            }
        }
        lock_.leave(lock_.value);
        return pid;
    }

    size_t count() const {
        if (!ready()) return 0;
        lock_.enter(lock_.value);
        const size_t value = count_;
        lock_.leave(lock_.value);
        return value;
    }

private:
    Lock lock_ {};
    Scope *head_ = nullptr;
    size_t count_ = 0;
    bool ready_ = false;
};

} // namespace Core
} // namespace ScanOwner
} // namespace LegacyWiFi

#endif
