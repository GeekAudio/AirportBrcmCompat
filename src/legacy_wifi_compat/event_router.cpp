#include "event_router.hpp"
#include <string.h>

#if !defined(AIRPORT_BRCM_EVENT_ROUTER_HOST_TEST)
#include <Headers/kern_patcher.hpp>
#endif

namespace LegacyWiFi {
namespace EventContracts {
namespace {

EventRouter router;

#if !defined(AIRPORT_BRCM_EVENT_ROUTER_HOST_TEST)
void routedPostMessage(void *interface, uint32_t eventCode,
                       void *payload, size_t payloadSize) {
    router.postMessage(interface, eventCode, payload, payloadSize);
}

void routedBSDPostMessage(char *bsdName, uint32_t eventCode,
                          void *payload, size_t payloadSize) {
    router.bsdPostMessage(bsdName, eventCode, payload, payloadSize);
}

constexpr const char *PostMessageSymbol = "__ZN16IO80211Interface11postMessageEjPvm";
constexpr const char *BSDPostMessageSymbol = "__Z27IO80211InterfacePostMessagePcjPvm";
#endif

} // namespace

EventRouter &shared() {
    return router;
}

bool EventRouter::configure(const RouterAPI &api,
                            const LoadedImage &provider,
                            const ProviderSymbols &providerSymbols) {
    if (__atomic_load_n(&configured_, __ATOMIC_ACQUIRE) ||
        !api.lookupBoundInterface || !api.eventContextIsUnsafe || !api.currentThread ||
        !api.shouldSuppress || !api.afterPost || !api.eventContextViolation ||
        !api.scopeLock.value || !api.scopeLock.enter || !api.scopeLock.leave ||
        !providerSymbols.getBSDName || !verifyProvider(provider, providerSymbols))
        return false;

    api_ = api;
    provider_ = provider;
    providerSymbols_ = providerSymbols;
    __atomic_store_n(&configured_, 1U, __ATOMIC_RELEASE);
    return true;
}

bool EventRouter::hasActiveVerifiedProvider(
        const LoadedImage &provider,
        const ProviderSymbols &providerSymbols) const {
    if (!ready() || provider.mappedHeader != provider_.mappedHeader ||
        provider.mappedSize != provider_.mappedSize) return false;
    return providerSymbols.getBSDName == providerSymbols_.getBSDName &&
        providerSymbols.postMessage == providerSymbols_.postMessage &&
        providerSymbols.postMessageBSD == providerSymbols_.postMessageBSD &&
        providerSymbols.scanManagerScanDone ==
            providerSymbols_.scanManagerScanDone &&
        providerSymbols.kevPostMsg == providerSymbols_.kevPostMsg;
}

bool EventRouter::admitDriver(const LoadedImage &driver, DriverKind kind,
                              const DriverSymbols &driverSymbols) {
    if (!__atomic_load_n(&configured_, __ATOMIC_ACQUIRE) ||
        !verifyDriver(driver, kind, driverSymbols, provider_, providerSymbols_))
        return false;
    const uint32_t bit = 1U << static_cast<uint8_t>(kind);
    __atomic_fetch_or(&admittedDriverMask_, bit, __ATOMIC_RELEASE);
    return true;
}

bool EventRouter::activateRoutes() {
    if (!__atomic_load_n(&configured_, __ATOMIC_ACQUIRE) ||
        !originalPostMessage_ || !originalBSDPostMessage_) return false;
    __atomic_store_n(&routesActive_, 1U, __ATOMIC_RELEASE);
    return true;
}

bool EventRouter::ready() const {
    return __atomic_load_n(&configured_, __ATOMIC_ACQUIRE) &&
        __atomic_load_n(&routesActive_, __ATOMIC_ACQUIRE) &&
        originalPostMessage_ && originalBSDPostMessage_ && api_.lookupBoundInterface &&
        api_.eventContextIsUnsafe && api_.currentThread &&
        api_.shouldSuppress && api_.afterPost && api_.eventContextViolation &&
        api_.scopeLock.value && api_.scopeLock.enter && api_.scopeLock.leave &&
        __atomic_load_n(&admittedDriverMask_, __ATOMIC_ACQUIRE) != 0;
}

int EventRouter::matchingDriver(void *interface,
                               char bsdName[InterfaceNameSize]) const {
    if (!interface || !ready()) return -1;
    int selected = -1;
    char selectedName[InterfaceNameSize] {};
    const uint32_t mask = __atomic_load_n(&admittedDriverMask_, __ATOMIC_ACQUIRE);
    for (uint8_t index = 0; index < 2; ++index) {
        if (!(mask & (1U << index))) continue;
        const auto kind = static_cast<DriverKind>(index);
        char candidate[InterfaceNameSize] {};
        if (!api_.lookupBoundInterface(api_.context, interface, kind, candidate) ||
            !validBSDName(candidate)) continue;
        if (selected >= 0) return -1; // Ambiguous class/family is never admitted.
        selected = index;
        memcpy(selectedName, candidate, sizeof(selectedName));
    }
    if (selected >= 0 && bsdName) memcpy(bsdName, selectedName, sizeof(selectedName));
    return selected;
}

bool EventRouter::supportsInterface(void *interface, DriverKind kind) const {
    if (!ready()) return false;
    const uint8_t index = static_cast<uint8_t>(kind);
    if (index > static_cast<uint8_t>(DriverKind::Broadcom43224) ||
        !(__atomic_load_n(&admittedDriverMask_, __ATOMIC_ACQUIRE) & (1U << index)))
        return false;
    char bsdName[InterfaceNameSize] {};
    return interface && api_.lookupBoundInterface(api_.context, interface, kind, bsdName);
}

bool EventRouter::mayAdvertiseCapability46(void *interface) const {
    return matchingDriver(interface) >= 0;
}

bool EventRouter::isScanEvent(uint32_t eventCode, void *payload, size_t payloadSize) {
    return payload == nullptr && payloadSize == 0 &&
        (eventCode == ScanDoneEventCode || eventCode == ScanCacheUpdatedEventCode);
}

bool EventRouter::isLifecycleEvent(uint32_t eventCode, void *payload,
                                   size_t payloadSize) {
    return payload == nullptr && payloadSize == 0 &&
        (eventCode == SSIDChangedEventCode ||
         eventCode == BSSIDChangedEventCode ||
         eventCode == RSNHandshakeCompleteEventCode);
}

bool EventRouter::providerBSDPayload(uint32_t eventCode, void *payload,
                                     size_t payloadSize, void *&bsdPayload,
                                     size_t &bsdPayloadSize) {
    bsdPayload = nullptr;
    bsdPayloadSize = 0;
    if (isScanEvent(eventCode, payload, payloadSize)) {
        bsdPayload = payload;
        bsdPayloadSize = payloadSize;
        return true;
    }
    if (isLifecycleEvent(eventCode, payload, payloadSize)) return true;
    if (eventCode != LinkStateEventCode || !payload) return false;

    // Validate the complete wrapper before opening a scope. The provider's
    // code-4 BSD helper receives the selected opaque value, without its TLV.
    LinkEventProjection projection{};
    if (!projectLinkEventPayload(static_cast<const uint8_t *>(payload),
                                 payloadSize, &projection)) return false;
    bsdPayload = const_cast<uint8_t *>(projection.payload);
    bsdPayloadSize = projection.payloadSize;
    return true;
}

bool EventRouter::validBSDName(const char *name) {
    if (!name) return false;
    for (size_t index = 0; index < InterfaceNameSize; ++index) {
        if (name[index] == '\0') return index != 0;
    }
    return false;
}

bool EventRouter::sameBSDName(const char *left, const char *right) {
    if (!validBSDName(left) || !validBSDName(right)) return false;
    for (size_t index = 0; index < InterfaceNameSize; ++index) {
        if (left[index] != right[index]) return false;
        if (left[index] == '\0') return true;
    }
    return false;
}

void EventRouter::callOriginalPostMessage(void *interface, uint32_t eventCode,
                                          void *payload, size_t payloadSize) const {
    if (originalPostMessage_)
        originalPostMessage_(interface, eventCode, payload, payloadSize);
}

void EventRouter::callOriginalBSDPostMessage(char *bsdName, uint32_t eventCode,
                                             void *payload, size_t payloadSize) const {
    if (originalBSDPostMessage_)
        originalBSDPostMessage_(bsdName, eventCode, payload, payloadSize);
}

bool EventRouter::addScope(PostMessageScope &scope) {
    api_.scopeLock.enter(api_.scopeLock.value);
    scope.next = scopes_;
    scopes_ = &scope;
    api_.scopeLock.leave(api_.scopeLock.value);
    return true;
}

bool EventRouter::removeScope(PostMessageScope &scope) {
    api_.scopeLock.enter(api_.scopeLock.value);
    bool observed = false;
    for (auto **current = &scopes_; *current; current = &(*current)->next) {
        if (*current == &scope) {
            *current = scope.next;
            observed = scope.nativeBSDObserved;
            break;
        }
    }
    scope.next = nullptr;
    api_.scopeLock.leave(api_.scopeLock.value);
    return observed;
}

PostMessageScope *EventRouter::findScopeLocked(const char *bsdName,
                                               uint32_t eventCode,
                                               void *payload,
                                               size_t payloadSize,
                                               uintptr_t thread) const {
    for (PostMessageScope *scope = scopes_; scope; scope = scope->next) {
        if (scope->thread == thread && scope->eventCode == eventCode &&
            scope->payload == payload &&
            scope->payloadSize == payloadSize &&
            sameBSDName(scope->bsdName, bsdName)) return scope;
    }
    return nullptr;
}

void EventRouter::postMessage(void *interface, uint32_t eventCode,
                              void *payload, size_t payloadSize) {
    // A same-thread interrupt can preempt an active synchronous scope. Keep
    // the provider's native path intact, but do not create a scope that could
    // confuse the interrupted thread's helper or run scan sequencing on its
    // stack. The sequence receives an IRQ-safe failure notification after
    // the provider has completed its synchronous side effects.
    if (ready() && api_.eventContextIsUnsafe(api_.context)) {
        callOriginalPostMessage(interface, eventCode, payload, payloadSize);
        if (isScanEvent(eventCode, payload, payloadSize) &&
            matchingDriver(interface) >= 0)
            api_.eventContextViolation(api_.context, interface, eventCode);
        return;
    }
    char bsdName[InterfaceNameSize] {};
    void *bsdPayload = nullptr;
    size_t bsdPayloadSize = 0;
    if (!ready() || !providerBSDPayload(eventCode, payload, payloadSize,
                                        bsdPayload, bsdPayloadSize) ||
        matchingDriver(interface, bsdName) < 0) {
        callOriginalPostMessage(interface, eventCode, payload, payloadSize);
        return;
    }
    const uintptr_t thread = api_.currentThread(api_.context);
    if (!thread) {
        callOriginalPostMessage(interface, eventCode, payload, payloadSize);
        return;
    }

    PostMessageScope scope;
    scope.interface = interface;
    scope.thread = thread;
    for (size_t index = 0; index < InterfaceNameSize; ++index) {
        scope.bsdName[index] = bsdName[index];
        if (bsdName[index] == '\0') break;
    }
    scope.eventCode = eventCode;
    // Scope identity uses the exact payload the provider passes to its BSD
    // helper. For code 4 this is the value after TLV unwrapping; lifecycle
    // events use the pinned null/zero shape.
    scope.payload = bsdPayload;
    scope.payloadSize = bsdPayloadSize;
    scope.suppress = isScanEvent(eventCode, payload, payloadSize) &&
        api_.shouldSuppress(api_.context, interface, eventCode);
    if (!addScope(scope)) {
        callOriginalPostMessage(interface, eventCode, payload, payloadSize);
        return;
    }

    callOriginalPostMessage(interface, eventCode, payload, payloadSize);
    const bool helperObserved = removeScope(scope);
    char stillBoundName[InterfaceNameSize] {};
    const bool stillBound = matchingDriver(interface, stillBoundName) >= 0 &&
        sameBSDName(scope.bsdName, stillBoundName);
    if (stillBound && !scope.suppress && !helperObserved)
        callOriginalBSDPostMessage(stillBoundName, eventCode,
                                   scope.payload, scope.payloadSize);
    // This callback may submit the next single scan. It must remain after the
    // original routine and any missing-BSD-route repair above.
    if (stillBound && isScanEvent(eventCode, payload, payloadSize))
        api_.afterPost(api_.context, interface, eventCode);
}

void EventRouter::bsdPostMessage(char *bsdName, uint32_t eventCode,
                                 void *payload, size_t payloadSize) {
    if (!originalBSDPostMessage_) return;
    bool suppress = false;
    const bool supportedBSDPayload = isScanEvent(eventCode, payload, payloadSize) ||
        isLifecycleEvent(eventCode, payload, payloadSize) ||
        (eventCode == LinkStateEventCode && payload &&
         payloadSize <= MaximumEventPayloadSize);
    if (ready() && !api_.eventContextIsUnsafe(api_.context) &&
        supportedBSDPayload && validBSDName(bsdName)) {
        const uintptr_t thread = api_.currentThread(api_.context);
        api_.scopeLock.enter(api_.scopeLock.value);
        PostMessageScope *scope = thread
            ? findScopeLocked(bsdName, eventCode, payload, payloadSize, thread) : nullptr;
        if (scope) {
            scope->nativeBSDObserved = true;
            suppress = scope->suppress;
        }
        api_.scopeLock.leave(api_.scopeLock.value);
    }
    if (!suppress)
        callOriginalBSDPostMessage(bsdName, eventCode, payload, payloadSize);
}

bool EventRouter::publishManaged(void *interface, uint32_t eventCode) {
    char bsdName[InterfaceNameSize] {};
    if (!ready() || api_.eventContextIsUnsafe(api_.context) ||
        matchingDriver(interface, bsdName) < 0 ||
        !isScanEvent(eventCode, nullptr, 0)) return false;
    // This direct trampoline deliberately bypasses both installed hooks.
    callOriginalBSDPostMessage(bsdName, eventCode, nullptr, 0);
    return true;
}

#if !defined(AIRPORT_BRCM_EVENT_ROUTER_HOST_TEST)
bool install(KernelPatcher &patcher, size_t index,
             const LoadedImage &provider,
             const ProviderSymbols &providerSymbols,
             const RouterAPI &api) {
    EventRouter &target = shared();
    if (!target.configure(api, provider, providerSymbols)) return false;

    patcher.clearError();
    KernelPatcher::RouteRequest postRoute(PostMessageSymbol,
        routedPostMessage, target.postMessageTrampoline());
    if (!patcher.routeMultiple(index, &postRoute, 1,
            reinterpret_cast<mach_vm_address_t>(provider.mappedHeader),
            provider.mappedSize) ||
        patcher.getError() != KernelPatcher::Error::NoError ||
        !target.postMessageTrampoline()) {
        patcher.clearError();
        return false;
    }

    patcher.clearError();
    KernelPatcher::RouteRequest bsdRoute(BSDPostMessageSymbol,
        routedBSDPostMessage, target.bsdPostMessageTrampoline());
    if (!patcher.routeMultiple(index, &bsdRoute, 1,
            reinterpret_cast<mach_vm_address_t>(provider.mappedHeader),
            provider.mappedSize) ||
        patcher.getError() != KernelPatcher::Error::NoError ||
        !target.bsdPostMessageTrampoline()) {
        patcher.clearError();
        return false;
    }
    return target.activateRoutes();
}
#endif

} // namespace EventContracts
} // namespace LegacyWiFi
