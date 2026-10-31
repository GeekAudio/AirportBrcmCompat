// Mirrors audited legacy lifecycle, scan, and link-state events when
// IO80211ElCap selects its gated data-path route. The original postMessage
// always runs; scan suppression is applied only at the BSD-event edge.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_EVENT_ROUTER_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_EVENT_ROUTER_HPP

#include "event_contracts.hpp"

class KernelPatcher;

namespace LegacyWiFi {
namespace EventContracts {

using PostMessageMethod = void (*)(void *interface, uint32_t eventCode,
                                   void *payload, size_t payloadSize);
using LookupBoundInterfaceMethod = bool (*)(void *context, void *interface,
                                            DriverKind kind,
                                            char bsdName[InterfaceNameSize]);
using BSDPostMessageMethod = void (*)(char *bsdName, uint32_t eventCode,
                                      void *payload, size_t payloadSize);

struct RouterLock {
    void *value = nullptr;
    void (*enter)(void *) = nullptr;
    void (*leave)(void *) = nullptr;
};

struct RouterAPI {
    void *context = nullptr;
    // Reads a retained, prevalidated interface binding. This callback must be
    // safe at interrupt level and must not query IOKit or allocate.
    LookupBoundInterfaceMethod lookupBoundInterface = nullptr;
    // An interrupt may interrupt a thread while one of its stack scopes is
    // active. Interrupt context and disabled-interrupt sections both forbid
    // sleepable event follow-up and must not match an interrupted scope.
    bool (*eventContextIsUnsafe)(void *context) = nullptr;
    uintptr_t (*currentThread)(void *context) = nullptr;
    bool (*shouldSuppress)(void *context, void *interface,
                           uint32_t eventCode) = nullptr;
    // Called after the original postMessage has returned, including its
    // synchronous ScanManager/cache work and any nested code-15 notification.
    void (*afterPost)(void *context, void *interface,
                      uint32_t eventCode) = nullptr;
    // IRQ-safe failure notification. The receiver may only record the
    // violation atomically and submit a preallocated deferred completion; it
    // must not run the coordinator or allocate from the event stack.
    void (*eventContextViolation)(void *context, void *interface,
                                  uint32_t eventCode) = nullptr;
    RouterLock scopeLock {};
};

struct PostMessageScope {
    void *interface = nullptr;
    uintptr_t thread = 0;
    char bsdName[InterfaceNameSize] {};
    uint32_t eventCode = 0;
    // Exact payload pointer/length expected at IO80211InterfacePostMessage.
    // Code 4 stores the opaque TLV value after the provider strips its header.
    void *payload = nullptr;
    size_t payloadSize = 0;
    bool suppress = false;
    bool nativeBSDObserved = false;
    PostMessageScope *next = nullptr;
    PostMessageScope() = default;
    PostMessageScope(const PostMessageScope &) = delete;
    PostMessageScope &operator=(const PostMessageScope &) = delete;
};

class EventRouter {
public:
    EventRouter() = default;
    EventRouter(const EventRouter &) = delete;
    EventRouter &operator=(const EventRouter &) = delete;

    bool configure(const RouterAPI &api,
                   const LoadedImage &provider,
                   const ProviderSymbols &providerSymbols);
    // Matches only the exact image and resolved symbols whose original bytes
    // passed configure's verifier before this router installed its hooks.
    // Requires the route and a driver admission to be active.
    bool hasActiveVerifiedProvider(const LoadedImage &provider,
                                   const ProviderSymbols &providerSymbols) const;
    bool admitDriver(const LoadedImage &driver, DriverKind kind,
                     const DriverSymbols &driverSymbols);
    bool activateRoutes();

    bool ready() const;
    bool supportsInterface(void *interface, DriverKind kind) const;
    bool mayAdvertiseCapability46(void *interface) const;

    // Exact four-argument method ABI. Always invokes the original first;
    // only scan events report completion to the scan-sequence coordinator.
    void postMessage(void *interface, uint32_t eventCode,
                     void *payload, size_t payloadSize);

    // Exact provider helper ABI. A matching suppressed scope drops only the
    // outward BSD notification; otherwise the original helper always runs.
    void bsdPostMessage(char *bsdName, uint32_t eventCode,
                        void *payload, size_t payloadSize);

    // Queue completion bypasses postMessage intentionally: it emits the
    // manager's final BSD event pair without re-running scan/cache handlers.
    bool publishManaged(void *interface, uint32_t eventCode);

    // Slots receive Lilu's original-function trampolines directly.
    PostMessageMethod &postMessageTrampoline() { return originalPostMessage_; }
    BSDPostMessageMethod &bsdPostMessageTrampoline() { return originalBSDPostMessage_; }

private:
    RouterAPI api_ {};
    LoadedImage provider_ {};
    ProviderSymbols providerSymbols_ {};
    PostMessageMethod originalPostMessage_ = nullptr;
    BSDPostMessageMethod originalBSDPostMessage_ = nullptr;
    PostMessageScope *scopes_ = nullptr;
    uint32_t admittedDriverMask_ = 0;
    uint32_t configured_ = 0;
    uint32_t routesActive_ = 0;

    static bool isScanEvent(uint32_t eventCode, void *payload, size_t payloadSize);
    static bool isLifecycleEvent(uint32_t eventCode, void *payload,
                                 size_t payloadSize);
    static bool providerBSDPayload(uint32_t eventCode, void *payload,
                                   size_t payloadSize, void *&bsdPayload,
                                   size_t &bsdPayloadSize);
    static bool validBSDName(const char *name);
    static bool sameBSDName(const char *left, const char *right);
    int matchingDriver(void *interface,
                       char bsdName[InterfaceNameSize] = nullptr) const;
    void callOriginalPostMessage(void *interface, uint32_t eventCode,
                                 void *payload, size_t payloadSize) const;
    void callOriginalBSDPostMessage(char *bsdName, uint32_t eventCode,
                                    void *payload, size_t payloadSize) const;
    bool addScope(PostMessageScope &scope);
    bool removeScope(PostMessageScope &scope);
    PostMessageScope *findScopeLocked(const char *bsdName, uint32_t eventCode,
                                      void *payload, size_t payloadSize,
                                      uintptr_t thread) const;
};

// Installs the two hooks only after verifying the provider's loaded Mach-O
// image and routes both endpoints against the exact provider image range.
bool install(KernelPatcher &patcher, size_t index,
             const LoadedImage &provider,
             const ProviderSymbols &providerSymbols,
             const RouterAPI &api);

// Shared router storage used by the provider hooks and loader observer.
EventRouter &shared();

} // namespace EventContracts
} // namespace LegacyWiFi

#endif
