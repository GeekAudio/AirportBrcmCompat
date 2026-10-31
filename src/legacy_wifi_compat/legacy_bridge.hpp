// Runtime adapters for the five-argument IO80211ElCap request handlers.
// The provider watcher must establish that these callbacks and copyIn return
// PCs belong to the audited ElCap image before constructing Runtime.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_LEGACY_BRIDGE_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_LEGACY_BRIDGE_HPP

#include "association_bridge.hpp"
#include "scan_bridge.hpp"
#include "scan_multiple_bridge.hpp"
#include "scan_single_bridge.hpp"

namespace LegacyWiFi {
namespace LegacyBridge {

using Request = ScanCompat::Request;
using Handler = int (*)(void *, void *, void *, Request *, bool);
using CopyIn = int (*)(void *, uint64_t, void *, size_t);
using CopyOut = int (*)(void *, const void *, uint64_t, size_t);

// A stack-owned request reservation remains linked for the entire synchronous
// handler call, including any temporary WorkLoop gate release downstream.
struct RequestScope {
    void *interface = nullptr;
    RequestScope *next = nullptr;
    RequestScope() = default;
    RequestScope(const RequestScope &) = delete;
    RequestScope &operator=(const RequestScope &) = delete;
};
struct RequestRegistry {
    static constexpr size_t Capacity = 8;
    AssociationBridge::Lock lock {};
    RequestScope *head = nullptr;
    bool add(RequestScope &scope);
    void remove(RequestScope &scope);
};

constexpr size_t LegacyAssociationCopySize = 0x1d0;
constexpr size_t LegacyAssociationObjectSize = AssociationCompat::LegacySize;
constexpr size_t AssociationStorageSize = AssociationCompat::NativeSize +
    AssociationCompat::NativeSize + LegacyAssociationObjectSize;

// A synchronous fixed-payload copyIn lease. It is keyed by all arguments that
// distinguish the ElCap copy site, consumes once, and never retains user data.
struct CopyInScope {
    uintptr_t thread = 0;
    uintptr_t caller = 0;
    void *controller = nullptr;
    uint64_t source = 0;
    const uint8_t *bytes = nullptr;
    size_t size = 0;
    bool consumed = false;
    CopyInScope *next = nullptr;
    CopyInScope() = default;
    CopyInScope(const CopyInScope &) = delete;
    CopyInScope &operator=(const CopyInScope &) = delete;
};

struct CopyInRegistry {
    AssociationBridge::Lock lock {};
    CopyInScope *head = nullptr;

    bool add(CopyInScope &scope);
    void remove(CopyInScope &scope);
    // -1 means this isn't a leased call. A partially matching call fails
    // closed, as does a second consume of the same lease.
    int consume(uintptr_t thread, uintptr_t caller, void *controller,
                uint64_t source, void *destination, size_t size);
};

// A one-shot GET12 copyOut lease. The original handler still produces and
// copies the eight raw capability bytes; only an exact same-thread output is
// eligible for setting the verified event capabilities for that schema.
struct CapabilityCopyOutScope {
    uintptr_t thread = 0;
    void *controller = nullptr;
    uint64_t destination = 0;
    uint8_t *bytes = nullptr;
    size_t size = 0;
    bool scanDone46 = false;
    bool consumed = false;
    CapabilityCopyOutScope *next = nullptr;
    CapabilityCopyOutScope() = default;
    CapabilityCopyOutScope(const CapabilityCopyOutScope &) = delete;
    CapabilityCopyOutScope &operator=(const CapabilityCopyOutScope &) = delete;
};

struct CapabilityCopyOutRegistry {
    AssociationBridge::Lock lock {};
    CapabilityCopyOutScope *head = nullptr;

    bool add(CapabilityCopyOutScope &scope);
    void remove(CapabilityCopyOutScope &scope);
    // -1 means unrelated. A same-thread partial match fails closed.
    int prepare(uintptr_t thread, void *controller, uint64_t destination,
                const void *source, size_t size, uint8_t **modifiedBytes);
};

// GET48's verified El Cap provider returns raw bytes through one exact
// copyOut call. Capture that call synchronously, then wrap the actual copied
// length in the modern 8-byte inline header after the original handler returns.
struct GetAPIEListCopyOutScope {
    uintptr_t thread = 0;
    uintptr_t caller = 0;
    void *controller = nullptr;
    uint64_t destination = 0;
    uint8_t *bytes = nullptr;
    size_t capacity = 0;
    size_t capturedSize = 0;
    bool consumed = false;
    GetAPIEListCopyOutScope *next = nullptr;
    GetAPIEListCopyOutScope() = default;
    GetAPIEListCopyOutScope(const GetAPIEListCopyOutScope &) = delete;
    GetAPIEListCopyOutScope &operator=(const GetAPIEListCopyOutScope &) = delete;
};

struct GetAPIEListCopyOutRegistry {
    static constexpr size_t Capacity = 8;
    AssociationBridge::Lock lock {};
    GetAPIEListCopyOutScope *head = nullptr;

    bool add(GetAPIEListCopyOutScope &scope);
    void remove(GetAPIEListCopyOutScope &scope);
    // -1 means unrelated. A same-thread partial/duplicate match fails closed.
    int capture(uintptr_t thread, uintptr_t caller, void *controller,
                uint64_t destination, const void *source, size_t size,
                size_t *capturedSize);
};

struct API {
    Handler getScanResult = nullptr;
    Handler getCapabilities = nullptr;
    Handler getStateReq = nullptr;
    Handler getAPIEList = nullptr;
    Handler setAssociateRequest = nullptr;
    Handler setScanRequestMultiple = nullptr;
    Handler setScanRequest = nullptr;
    Handler setAuthType = nullptr;
    Handler setDisassociate = nullptr;
    // Optional metadata operation. Receives the single owned request snapshot's
    // decoded values; errors must preserve incomplete-action information even
    // if the native disconnect itself already happened.
    int (*setDisassociateMetadata)(void *, void *, void *, Request *, bool,
                                   uint32_t reason, uint32_t flush) = nullptr;

    CopyIn copyIn = nullptr;       // Must be the unhooked original trampoline.
    CopyOut copyOut = nullptr;
    void *(*allocate)(size_t) = nullptr;
    void (*deallocate)(void *, size_t) = nullptr;
    uintptr_t (*currentThread)() = nullptr;
    void *(*scanManager)(void *interface) = nullptr;
    ScanBridge::GetResult getResult = nullptr;
    bool (*primaryInterface)(void *controller, void *interface,
                             const char requestName[16]) = nullptr;
    bool (*supportsMultiple)(void *controller, void *interface) = nullptr;
    // Installer/event-contract gate: includes exact provider/controller proof
    // and the currently eligible native event transport. Every known schema
    // consumes raw capability22; only the 14+ schemas also consume bit46.
    bool (*admitScanEventCapabilities)(void *controller, void *interface) = nullptr;

    // Optional 43224 owner-controlled scan sequence. These callbacks are
    // either supplied together or omitted; a partially configured result
    // lease must never consume a record without a commit/abort operation.
    void *sequenceContext = nullptr;
    int (*currentPID)() = nullptr;
    int (*submitSingleSequence)(void *, void *, void *, const uint8_t *, size_t) = nullptr;
    bool (*peekManagedGet11)(void *, void *, void *, int, uint8_t *, size_t,
                            uint64_t *, int *) = nullptr;
    bool (*commitManagedGet11)(void *, void *, int, uint64_t, bool) = nullptr;
    // Exact ElCap-sized calls bypass request conversion. Admission must still
    // reject overlap with an owned sequence, while result invalidation waits
    // until the native handler confirms it accepted the operation.
    int (*checkManagedScanBusy)(void *, void *) = nullptr;
    int (*invalidateManagedResults)(void *, void *) = nullptr;
    int (*prepareAssociation)(void *, void *) = nullptr;

    // Return PCs of the audited ElCap copyIn calls: setAssociateRequest's
    // 0x4d164 and setScanRequestMultiple's 0x4eed2 relative to the verified
    // provider text base. The hook layer resolves them to runtime addresses.
    uintptr_t associationCopyInCaller = 0;
    uintptr_t multipleCopyInCaller = 0;
    uintptr_t singleCopyInCaller = 0;
    uintptr_t getAPIEListCopyOutCaller = 0;
    uintptr_t authCopyInCaller = 0;
    AssociationBridge::Lock registryLock {};
};

class Runtime {
public:
    Runtime() = default;
    explicit Runtime(const API &api);
    // Publish a complete immutable callback table once, before any hooks route
    // into this object. Returns false for incomplete APIs or repeat calls.
    bool prepare(const API &api);
    bool ready() const;

    // These signatures exactly match the five-argument ElCap handlers.
    int getScanResult(void *controller, void *interface, void *virtualInterface,
                      Request *request, bool user64);
    int getCapabilities(void *controller, void *interface, void *virtualInterface,
                        Request *request, bool user64);
    int getStateReq(void *controller, void *interface, void *virtualInterface,
                    Request *request, bool user64);
    int getAPIEList(void *controller, void *interface, void *virtualInterface,
                    Request *request, bool user64);
    int setAssociateRequest(void *controller, void *interface, void *virtualInterface,
                            Request *request, bool user64);
    int setAuthType(void *controller, void *interface, void *virtualInterface,
                    Request *request, bool user64);
    int setDisassociate(void *controller, void *interface, void *virtualInterface,
                        Request *request, bool user64);
    int setScanRequestMultiple(void *controller, void *interface, void *virtualInterface,
                               Request *request, bool user64);
    int setScanRequest(void *controller, void *interface, void *virtualInterface,
                      Request *request, bool user64);

    // The copyIn detour passes its actual return PC here. Unmatched operations
    // go straight to the saved original; matching operations consume one exact
    // converted payload. GET12's exact eight-byte copyOut lease may add only
    // the separately admitted scan-event bits. GET48's exact provider copyOut
    // call is captured into a bounded local buffer. Event delivery is owned by
    // the event router, which observes the original BSD path to avoid duplicates.
    int copyIn(void *controller, uint64_t source, void *destination, size_t size,
               uintptr_t caller);
    int copyOut(void *controller, const void *source, uint64_t destination, size_t size,
                uintptr_t caller = 0);

private:
    API api_;
    bool prepared_ = false;
    AssociationBridge::Registry associationRegistry_ {};
    CopyInRegistry multipleRegistry_ {};
    CapabilityCopyOutRegistry capabilityCopyOutRegistry_ {};
    GetAPIEListCopyOutRegistry getAPIEListCopyOutRegistry_ {};
    RequestRegistry requestRegistry_ {};

    bool isPrimary(void *controller, void *interface, const Request *request) const;
    int original(Handler handler, void *controller, void *interface,
                 void *virtualInterface, Request *request, bool user64) const;
    int dispatchExactLegacy(Handler handler, void *controller, void *interface,
                            void *virtualInterface, Request *request, bool user64) const;
    int dispatchProjectedMultiple(void *controller, void *interface,
                                   void *virtualInterface, Request *request,
                                   bool user64, const uint8_t *projected);
};

} // namespace LegacyBridge
} // namespace LegacyWiFi

#endif
