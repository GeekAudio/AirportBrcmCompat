#include "legacy_bridge.hpp"
#include "bsd_get_adapter.hpp"
#include "bsd_set_adapter.hpp"

#include <sys/errno.h>

namespace LegacyWiFi {
namespace LegacyBridge {
namespace {

bool overlaps(const void *a, size_t an, const void *b, size_t bn) {
    const uintptr_t x = reinterpret_cast<uintptr_t>(a);
    const uintptr_t y = reinterpret_cast<uintptr_t>(b);
    return x <= y ? y - x < an : x - y < bn;
}

struct AssociationBuffer {
    const API &api;
    uint8_t *bytes;
    explicit AssociationBuffer(const API &value)
        : api(value), bytes(static_cast<uint8_t *>(value.allocate(AssociationStorageSize))) {}
    ~AssociationBuffer() {
        if (bytes) {
            memset(bytes, 0, AssociationStorageSize);
            api.deallocate(bytes, AssociationStorageSize);
        }
    }
    AssociationBuffer(const AssociationBuffer &) = delete;
    AssociationBuffer &operator=(const AssociationBuffer &) = delete;
};

struct ScanBuffer {
    const API &api;
    size_t size;
    uint8_t *bytes;
    explicit ScanBuffer(const API &value,size_t nativeSize,
                            size_t targetSize=ScanMultipleBridge::ElCapSize)
        : api(value), size(nativeSize+targetSize),
          bytes(static_cast<uint8_t *>(value.allocate(size))) {}
    ~ScanBuffer() {
        if (bytes) {
            memset(bytes, 0, size);
            api.deallocate(bytes, size);
        }
    }
    ScanBuffer(const ScanBuffer &) = delete;
    ScanBuffer &operator=(const ScanBuffer &) = delete;
};

struct RequestLength {
    Request &request;
    uint32_t saved;
    RequestLength(Request &value, uint32_t replacement)
        : request(value), saved(value.length) { request.length = replacement; }
    ~RequestLength() { request.length = saved; }
    RequestLength(const RequestLength &) = delete;
    RequestLength &operator=(const RequestLength &) = delete;
};

struct RequestGuard {
    RequestRegistry &registry;
    RequestScope scope;
    bool linked = false, admitted = true;
    RequestGuard(RequestRegistry &value,void *interface,bool enabled):registry(value) {
        if (enabled && interface) {
            scope.interface=interface;
            admitted=linked=registry.add(scope);
        }
    }
    ~RequestGuard() {if (linked) registry.remove(scope);}
    RequestGuard(const RequestGuard &)=delete;
    RequestGuard &operator=(const RequestGuard &)=delete;
};

struct StackBytes {
    uint8_t *bytes;
    size_t size;
    StackBytes(uint8_t *p,size_t n):bytes(p),size(n) {}
    ~StackBytes() {if (bytes) memset(bytes,0,size);}
    StackBytes(const StackBytes &)=delete;
    StackBytes &operator=(const StackBytes &)=delete;
};

} // namespace

bool RequestRegistry::add(RequestScope &scope) {
    if (!scope.interface || !lock.value || !lock.enter || !lock.leave) return false;
    lock.enter(lock.value);
    size_t count=0;
    for (auto *p=head;p;p=p->next) {
        if (p->interface==scope.interface || ++count>=Capacity) {
            lock.leave(lock.value);
            return false;
        }
    }
    scope.next=head;head=&scope;
    lock.leave(lock.value);
    return true;
}
void RequestRegistry::remove(RequestScope &scope) {
    if (!lock.value || !lock.enter || !lock.leave) return;
    lock.enter(lock.value);
    for (auto **p=&head;*p;p=&(*p)->next) {
        if (*p==&scope) {*p=scope.next;break;}
    }
    scope.next=nullptr;
    lock.leave(lock.value);
}

bool CopyInRegistry::add(CopyInScope &scope) {
    if (!scope.thread || !scope.caller || !scope.controller || !scope.source ||
        !scope.bytes || !scope.size || !lock.value || !lock.enter || !lock.leave) return false;
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

void CopyInRegistry::remove(CopyInScope &scope) {
    if (!lock.value || !lock.enter || !lock.leave) return;
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

int CopyInRegistry::consume(uintptr_t thread, uintptr_t caller, void *controller,
                            uint64_t source, void *destination, size_t size) {
    if (!lock.value || !lock.enter || !lock.leave) return -1;
    lock.enter(lock.value);
    for (auto *p = head; p; p = p->next) {
        if (p->thread != thread) continue;
        int error = EINVAL;
        if (p->caller == caller && !p->consumed && p->controller == controller &&
            p->source == source && p->size == size && destination &&
            !overlaps(destination, size, p->bytes, p->size)) {
            memcpy(destination, p->bytes, size);
            p->consumed = true;
            error = 0;
        }
        lock.leave(lock.value);
        return error;
    }
    lock.leave(lock.value);
    return -1;
}

bool CapabilityCopyOutRegistry::add(CapabilityCopyOutScope &scope) {
    if (!scope.thread || !scope.controller || !scope.destination || !scope.bytes ||
        scope.size != 8 || !lock.value || !lock.enter || !lock.leave) return false;
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

void CapabilityCopyOutRegistry::remove(CapabilityCopyOutScope &scope) {
    if (!lock.value || !lock.enter || !lock.leave) return;
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

int CapabilityCopyOutRegistry::prepare(uintptr_t thread, void *controller,
                                       uint64_t destination, const void *source,
                                       size_t size, uint8_t **modifiedBytes) {
    if (!lock.value || !lock.enter || !lock.leave || !modifiedBytes) return -1;
    *modifiedBytes = nullptr;
    lock.enter(lock.value);
    for (auto *p = head; p; p = p->next) {
        if (p->thread != thread) continue;
        int error = EINVAL;
        if (!p->consumed && p->controller == controller &&
            p->destination == destination && p->size == size && size == 8 && source) {
            memcpy(p->bytes, source, size);
            p->bytes[2] |= 0x40; // Native BSD scan-event socket capability.
            if (p->scanDone46) p->bytes[5] |= 0x40; // 14+ semaphore completion.
            p->consumed = true;
            *modifiedBytes = p->bytes;
            error = 0;
        }
        lock.leave(lock.value);
        return error;
    }
    lock.leave(lock.value);
    return -1;
}

bool GetAPIEListCopyOutRegistry::add(GetAPIEListCopyOutScope &scope) {
    if (!scope.thread || !scope.caller || !scope.controller ||
        !scope.destination || !scope.bytes ||
        scope.capacity != BSDGetAdapter::GetAPIEListLegacyCapacity ||
        !lock.value || !lock.enter || !lock.leave) return false;
    lock.enter(lock.value);
    size_t count=0;
    for (auto *p=head;p;p=p->next) {
        if (p->thread==scope.thread || ++count>=Capacity) {
            lock.leave(lock.value);
            return false;
        }
    }
    scope.capturedSize=0;
    scope.consumed=false;
    scope.next=head;
    head=&scope;
    lock.leave(lock.value);
    return true;
}

void GetAPIEListCopyOutRegistry::remove(GetAPIEListCopyOutScope &scope) {
    if (!lock.value || !lock.enter || !lock.leave) return;
    lock.enter(lock.value);
    for (auto **p=&head;*p;p=&(*p)->next) {
        if (*p==&scope) {
            *p=scope.next;
            break;
        }
    }
    scope.next=nullptr;
    lock.leave(lock.value);
}

int GetAPIEListCopyOutRegistry::capture(uintptr_t thread,uintptr_t caller,
                                        void *controller,uint64_t destination,
                                        const void *source,size_t size,
                                        size_t *capturedSize) {
    if (!lock.value || !lock.enter || !lock.leave || !capturedSize) return -1;
    lock.enter(lock.value);
    for (auto *p=head;p;p=p->next) {
        const bool sameThread=p->thread==thread;
        const bool sameOperation=p->caller==caller && p->controller==controller &&
            p->destination==destination;
        if (!sameThread && !sameOperation) continue;
        int error=EINVAL;
        if (sameThread && !p->consumed && p->caller==caller && p->controller==controller &&
            p->destination==destination && source && size<=p->capacity &&
            !overlaps(source,size,p->bytes,p->capacity)) {
            if (size) memcpy(p->bytes,source,size);
            p->capturedSize=size;
            p->consumed=true;
            *capturedSize=size;
            error=0;
        }
        lock.leave(lock.value);
        return error;
    }
    lock.leave(lock.value);
    return -1;
}

Runtime::Runtime(const API &api) {
    (void)prepare(api);
}

bool Runtime::prepare(const API &api) {
    if (prepared_ || !api.getScanResult || !api.getCapabilities ||
        !api.getStateReq || !api.getAPIEList ||
        !api.setAssociateRequest || !api.setScanRequestMultiple || !api.copyIn ||
        !api.copyOut || !api.allocate || !api.deallocate || !api.currentThread ||
        !api.scanManager || !api.getResult || !api.primaryInterface ||
        !api.associationCopyInCaller || !api.multipleCopyInCaller ||
        !api.registryLock.value || !api.registryLock.enter || !api.registryLock.leave)
        return false;

    const bool sequenceAny=api.currentPID || api.submitSingleSequence ||
        api.peekManagedGet11 || api.commitManagedGet11 || api.checkManagedScanBusy ||
        api.invalidateManagedResults || api.prepareAssociation;
    const bool sequenceAll=api.currentPID && api.submitSingleSequence &&
        api.peekManagedGet11 && api.commitManagedGet11 && api.checkManagedScanBusy &&
        api.invalidateManagedResults && api.prepareAssociation;
    if (sequenceAny && !sequenceAll) return false;
    if ((api.setScanRequest!=nullptr)!=(api.singleCopyInCaller!=0) ||
        (api.setAuthType!=nullptr)!=(api.authCopyInCaller!=0) ||
        (api.setDisassociateMetadata && !api.setDisassociate) ||
        !api.getAPIEListCopyOutCaller) return false;

    api_ = api;
    associationRegistry_.lock = api_.registryLock;
    multipleRegistry_.lock = api_.registryLock;
    capabilityCopyOutRegistry_.lock = api_.registryLock;
    getAPIEListCopyOutRegistry_.lock = api_.registryLock;
    requestRegistry_.lock = api_.registryLock;
    prepared_ = true;
    return true;
}

bool Runtime::ready() const {
    return prepared_ && api_.getScanResult && api_.getCapabilities && api_.getStateReq &&
        api_.getAPIEList && api_.setAssociateRequest &&
        api_.setScanRequestMultiple && api_.copyIn && api_.copyOut && api_.allocate &&
        api_.deallocate && api_.currentThread && api_.scanManager && api_.getResult &&
        api_.primaryInterface && api_.associationCopyInCaller && api_.multipleCopyInCaller &&
        api_.registryLock.value && api_.registryLock.enter && api_.registryLock.leave;
}

bool Runtime::isPrimary(void *controller, void *interface, const Request *request) const {
    return controller && interface && request && api_.primaryInterface &&
        api_.primaryInterface(controller, interface, request->interfaceName);
}

int Runtime::original(Handler handler, void *controller, void *interface,
                      void *virtualInterface, Request *request, bool user64) const {
    return handler ? handler(controller, interface, virtualInterface, request, user64) : ENXIO;
}

int Runtime::dispatchExactLegacy(Handler handler, void *controller, void *interface,
                                 void *virtualInterface, Request *request,
                                 bool user64) const {
    // The pinned ElCap handlers accept these fixed-size requests even when
    // virtualInterface/user64/reserved fields do not satisfy the modern
    // conversion path. Protect the same interface's managed queue regardless
    // of those fields, but preserve completed results if the native handler
    // rejects the request or its user copy fails.
    if (request && request->userData && api_.checkManagedScanBusy) {
        const int busy=api_.checkManagedScanBusy(api_.sequenceContext,interface);
        if (busy) return busy;
    }
    const int error=original(handler,controller,interface,virtualInterface,request,user64);
    if (!error && request && request->userData && api_.invalidateManagedResults) {
        const int invalidated=api_.invalidateManagedResults(api_.sequenceContext,interface);
        if (invalidated) return invalidated;
    }
    return error;
}

int Runtime::getScanResult(void *controller, void *interface, void *virtualInterface,
                           Request *request, bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!ready() || virtualInterface || !ScanBridge::targetsNativeGet11(request) ||
        !user64 || !isPrimary(controller, interface, request))
        return original(api_.getScanResult, controller, interface, virtualInterface, request, user64);

    ScanBridge::API scanAPI {
        api_.getScanResult, api_.allocate, api_.deallocate, api_.copyIn, api_.copyOut,
        api_.scanManager, api_.getResult, api_.primaryInterface
    };
    if (api_.peekManagedGet11) {
        uint8_t fixed[ScanBridge::FixedLegacyResultSize] {};
        uint64_t token=0;
        int error=0;
        const int pid=api_.currentPID();
        const bool managed=api_.peekManagedGet11(api_.sequenceContext,controller,
            interface,pid,fixed,sizeof(fixed),&token,&error);
        if (managed) {
            if (!error && !token) error=EIO;
            if (!error)
                error=ScanBridge::copyFixedSnapshot(scanAPI,controller,interface,
                                                    request,fixed,sizeof(fixed));
            const bool committed=!token || api_.commitManagedGet11(
                api_.sequenceContext,interface,pid,token,error==0);
            memset(fixed,0,sizeof(fixed));
            return error?error:(committed?0:ESTALE);
        }
        memset(fixed,0,sizeof(fixed));
    }
    return ScanBridge::handle(scanAPI, controller, interface, virtualInterface, request, user64);
}

int Runtime::getCapabilities(void *controller, void *interface, void *virtualInterface,
                             Request *request, bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    const bool knownCapacity = request &&
        (request->length == 12 || request->length == 13 || request->length == 16 ||
         request->length == 19 || request->length == 21);
    if (!ready() || !request || request->type != 12 || virtualInterface || !user64 ||
        request->value != 0 || request->padding != 0 || !knownCapacity ||
        !request->userData || !isPrimary(controller, interface, request) ||
        !api_.admitScanEventCapabilities ||
        !api_.admitScanEventCapabilities(controller, interface))
        return original(api_.getCapabilities, controller, interface, virtualInterface,
                        request, user64);

    uint8_t bytes[8] {};
    CapabilityCopyOutScope scope;
    scope.thread = api_.currentThread();
    scope.controller = controller;
    scope.destination = request->userData;
    scope.bytes = bytes;
    scope.size = sizeof(bytes);
    scope.scanDone46 = request->length>=16;
    if (!capabilityCopyOutRegistry_.add(scope)) return EBUSY;
    const int error = api_.getCapabilities(controller, interface, virtualInterface,
                                           request, user64);
    capabilityCopyOutRegistry_.remove(scope);
    if (error) return error;
    return scope.consumed ? 0 : EIO;
}

int Runtime::getStateReq(void *controller,void *interface,void *virtualInterface,
                         Request *request,bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!ready() || !request || request->type!=13 || virtualInterface || !user64 ||
        !BSDGetAdapter::stateUsesPointerEnvelope(request->length,request->userData) ||
        !isPrimary(controller,interface,request))
        return original(api_.getStateReq,controller,interface,virtualInterface,request,user64);

    uint64_t outputAddress=0;
    if (!BSDGetAdapter::addUserAddress(request->userData,
            BSDGetAdapter::GetStateValueOffset,
            BSDGetAdapter::GetStateValueSize,outputAddress)) return EINVAL;

    const int32_t savedValue=request->value;
    const int error=api_.getStateReq(controller,interface,virtualInterface,request,user64);
    if (error) return error;

    uint8_t output[BSDGetAdapter::GetStateValueSize] {};
    StackBytes clearOutput(output,sizeof(output));
    int adapted=BSDGetAdapter::encodeState(request->value,output);
    if (adapted) {
        request->value=savedValue;
        return adapted;
    }
    adapted=api_.copyOut(controller,output,outputAddress,sizeof(output));
    request->value=savedValue;
    return adapted;
}

int Runtime::getAPIEList(void *controller,void *interface,void *virtualInterface,
                         Request *request,bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!ready() || !request || request->type!=48 || virtualInterface || !user64 ||
        !BSDGetAdapter::ieListUsesHeaderEnvelope(request->length,request->userData) ||
        !isPrimary(controller,interface,request))
        return original(api_.getAPIEList,controller,interface,virtualInterface,request,user64);

    const uint32_t inputCapacity=request->length;
    uint8_t raw[BSDGetAdapter::GetAPIEListLegacyCapacity] {};
    StackBytes clearRaw(raw,sizeof(raw));
    GetAPIEListCopyOutScope scope;
    scope.thread=api_.currentThread();
    scope.caller=api_.getAPIEListCopyOutCaller;
    scope.controller=controller;
    scope.destination=request->userData;
    scope.bytes=raw;
    scope.capacity=sizeof(raw);
    if (!getAPIEListCopyOutRegistry_.add(scope)) return EBUSY;
    const int error=api_.getAPIEList(controller,interface,virtualInterface,request,user64);
    getAPIEListCopyOutRegistry_.remove(scope);
    if (error) return error;
    if (!scope.consumed || request->length!=scope.capturedSize) {
        request->length=inputCapacity;
        return EIO;
    }

    uint8_t output[BSDGetAdapter::GetAPIEListNativeMaximum] {};
    StackBytes clearOutput(output,sizeof(output));
    size_t outputSize=0;
    const int encoded=BSDGetAdapter::encodeIEList(raw,scope.capturedSize,
        output,sizeof(output),&outputSize);
    if (encoded) {
        request->length=inputCapacity;
        return encoded;
    }
    const int copied=api_.copyOut(controller,output,request->userData,outputSize);
    if (copied) {
        request->length=inputCapacity;
        return copied;
    }
    request->length=static_cast<uint32_t>(outputSize);
    return 0;
}

int Runtime::setDisassociate(void *controller,void *interface,void *virtualInterface,
                             Request *request,bool user64) {
    namespace D=BSDSetAdapter;
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!request || request->type!=22 || !request->length)
        return original(api_.setDisassociate,controller,interface,virtualInterface,request,user64);
    if (request->length!=D::DisassociateReasonSize && request->length!=D::DisassociateFlushSize)
        return EOPNOTSUPP;
    if (!ready() || !api_.setDisassociate) return ENXIO;
    if (!user64 || request->value || request->padding || !request->userData) return EINVAL;
    if (virtualInterface || !isPrimary(controller,interface,request)) return EOPNOTSUPP;
    const size_t size=request->length;
    uint64_t address=0;
    if (!BSDGetAdapter::addUserAddress(request->userData,0,size,address)) return EINVAL;
    uint8_t snapshot[D::DisassociateFlushSize] {};
    StackBytes clearSnapshot(snapshot,sizeof(snapshot));
    int error=api_.copyIn(controller,address,snapshot,size);
    if (error) return error;
    D::DisassociateMetadata metadata {};
    error=D::decodeDisassociate(snapshot,size,&metadata);
    if (error) return error;
    if (!isPrimary(controller,interface,request)) return ESTALE;
    if (metadata.reason || metadata.flush)
        return api_.setDisassociateMetadata ? api_.setDisassociateMetadata(
            controller,interface,virtualInterface,request,user64,metadata.reason,metadata.flush) : EOPNOTSUPP;
    // Zero reason and zero flush retain the provider's ordinary disconnect.
    // The pinned complete provider body never reads request data. It cannot
    // reread a user buffer changed after our single copyIn, so no copy lease
    // or mutation of the caller's request is necessary for this case.
    return original(api_.setDisassociate,controller,interface,virtualInterface,request,user64);
}

int Runtime::setAuthType(void *controller,void *interface,void *virtualInterface,
                         Request *request,bool user64) {
    namespace Auth=BSDSetAdapter;
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!request || request->type!=2 || request->length<=Auth::AuthLegacySize)
        return original(api_.setAuthType,controller,interface,virtualInterface,request,user64);
    // The fixed provider silently copies only 12 bytes. An unknown longer
    // record must never reach that truncating path as a successful SET.
    if (request->length!=Auth::AuthNativeSize) return EOPNOTSUPP;
    if (!ready() || !api_.setAuthType || !api_.authCopyInCaller) return ENXIO;
    if (!user64 || request->value || request->padding || !request->userData) return EINVAL;
    if (virtualInterface || !isPrimary(controller,interface,request)) return EOPNOTSUPP;
    uint64_t checkedAddress=0;
    if (!BSDGetAdapter::addUserAddress(request->userData,0,Auth::AuthNativeSize,
                                     checkedAddress)) return EINVAL;

    uint8_t native[Auth::AuthNativeSize] {},projected[Auth::AuthLegacySize] {};
    StackBytes clearNative(native,sizeof(native)),clearProjected(projected,sizeof(projected));
    int error=api_.copyIn(controller,checkedAddress,native,sizeof(native));
    if (error) return error;
    error=Auth::projectAuthType(native,sizeof(native),projected,sizeof(projected));
    if (error) return error;
    if (!isPrimary(controller,interface,request)) return ESTALE;

    // Deliver the checked snapshot at the exact old copy site. Re-reading
    // the user's prefix after checking the extension would allow a race.
    CopyInScope scope;
    scope.thread=api_.currentThread();scope.caller=api_.authCopyInCaller;
    scope.controller=controller;scope.source=request->userData;
    scope.bytes=projected;scope.size=sizeof(projected);
    if (!multipleRegistry_.add(scope)) return EBUSY;
    error=api_.setAuthType(controller,interface,virtualInterface,request,user64);
    multipleRegistry_.remove(scope);
    if (!error && !scope.consumed) return EIO;
    return error;
}

int Runtime::setAssociateRequest(void *controller, void *interface, void *virtualInterface,
                                 Request *request, bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!request || request->type != 20)
        return original(api_.setAssociateRequest, controller, interface, virtualInterface, request, user64);
    if (request->length == LegacyAssociationCopySize) {
        return dispatchExactLegacy(api_.setAssociateRequest,controller,interface,
                                   virtualInterface,request,user64);
    }
    if (!AssociationCompat::supportedRequestSize(request->length) &&
        !AssociationProfiles::legacyHeaderSize(request->length))
        return request->length > LegacyAssociationCopySize ? EOPNOTSUPP : EINVAL;
    // Once a known modern schema reaches the old handler, passing it through
    // would silently truncate it to ElCap's 464-byte copy. Reject every case
    // that cannot enter the bounded main-interface adapter.
    if (!ready() || virtualInterface || !user64 || request->value != 0 ||
        request->padding != 0 || !request->userData) return EINVAL;
    if (!isPrimary(controller, interface, request)) return EOPNOTSUPP;

    AssociationBuffer buffer(api_);
    if (!buffer.bytes) return ENOMEM;
    const size_t sourceSize = request->length;
    uint8_t *native = buffer.bytes;
    uint8_t *normalized = buffer.bytes + AssociationCompat::NativeSize;
    uint8_t *projected = normalized + AssociationCompat::NativeSize;

    int error = api_.copyIn(controller, request->userData, native, sourceSize);
    if (error) return error;

    if (AssociationProfiles::legacyHeaderSize(sourceSize)) {
        const auto profile = AssociationProfiles::convertLegacyHeader(
            native, sourceSize, projected, LegacyAssociationObjectSize);
        if (profile.error) return profile.error;
        const auto narrowed = AssociationBridge::narrowProjected(
            projected, LegacyAssociationObjectSize, normalized,
            LegacyAssociationCopySize);
        if (narrowed.error) return narrowed.error;
        memcpy(projected, normalized, LegacyAssociationCopySize);
    } else {
        const uint8_t *shared = native;
        if (sourceSize == AssociationProfiles::Sequoia15Size) {
            const auto profile = AssociationProfiles::normalizeSequoia15(
                native, sourceSize, normalized, AssociationCompat::NativeSize);
            if (profile.error) return profile.error;
            shared = normalized;
        }
        const auto converted = AssociationBridge::convert(
            shared, AssociationCompat::NativeSize, projected, LegacyAssociationCopySize);
        if (converted.error) return converted.error;
    }

    if (!isPrimary(controller, interface, request)) return ESTALE;
    if (api_.prepareAssociation) {
        const int prepared=api_.prepareAssociation(api_.sequenceContext,interface);
        if (prepared) return prepared;
    }
    AssociationBridge::Scope scope;
    scope.thread = api_.currentThread();
    scope.caller = api_.associationCopyInCaller;
    scope.controller = controller;
    scope.source = request->userData;
    scope.legacy = projected;
    if (!associationRegistry_.add(scope)) return EBUSY;

    {
        RequestLength narrowed(*request, LegacyAssociationCopySize);
        error = api_.setAssociateRequest(controller, interface, virtualInterface, request, user64);
    }
    associationRegistry_.remove(scope);
    if (!error && !scope.consumed) return EIO;
    return error;
}

int Runtime::setScanRequest(void *controller,void *interface,void *virtualInterface,
                            Request *request,bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    namespace Single=ScanSingleBridge;
    if (!request || request->type!=10)
        return original(api_.setScanRequest,controller,interface,virtualInterface,request,user64);
    if (request->length==Single::ElCapSize) {
        return dispatchExactLegacy(api_.setScanRequest,controller,interface,
                                   virtualInterface,request,user64);
    }
    Single::NativeLayout layout;
    if (!Single::nativeLayoutForSize(request->length,layout)) return EOPNOTSUPP;
    if (!ready() || !api_.setScanRequest || !api_.singleCopyInCaller) return ENXIO;
    if (!user64 || request->value || request->padding || !request->userData) return EINVAL;
    if (virtualInterface || !isPrimary(controller,interface,request)) return EOPNOTSUPP;
    // A separate canonical SET86 workspace is needed only for channel sets
    // that the fixed provider's single request cannot carry. It is heap-owned.
    ScanBuffer buffer(api_,request->length,ScanMultipleBridge::NativeSize);
    if (!buffer.bytes) return ENOMEM;
    uint8_t *native=buffer.bytes,*converted=buffer.bytes+request->length;
    int error=api_.copyIn(controller,request->userData,native,request->length);
    if (error) return error;
    const auto shape=Single::validateNativeShape(native,request->length,&layout);
    if (shape.error) return shape.error;
    if (!isPrimary(controller,interface,request)) return ESTALE;
    const auto projected=Single::convertToElCap(native,request->length,converted,Single::ElCapSize);
    if (projected.error) {
        // Normalization does not relax schema validation or silently omit a
        // policy field. The owned queue independently validates the result.
        const auto multiple=Single::normalizeToScanMultiple(native,request->length,
            converted,ScanMultipleBridge::NativeSize);
        if (multiple.error) return multiple.error;
        if (api_.supportsMultiple && api_.supportsMultiple(controller,interface)) {
            // 4331 already has a native multi-SSID consumer. Use its audited
            // SET86 copy site with an owned payload rather than truncating the
            // SET10 SSID list or passing a kernel address to user copyIn.
            ScanBuffer multiBuffer(api_,0);
            if (!multiBuffer.bytes) return ENOMEM;
            const auto narrowed=ScanMultipleBridge::convertToElCap(converted,
                ScanMultipleBridge::NativeSize,multiBuffer.bytes,
                ScanMultipleBridge::ElCapSize);
            if (narrowed.error) return narrowed.error;
            Request translated=*request;
            translated.type=86;
            return dispatchProjectedMultiple(controller,interface,virtualInterface,
                                               &translated,user64,multiBuffer.bytes);
        }
        if (!api_.submitSingleSequence) return EOPNOTSUPP;
        return api_.submitSingleSequence(api_.sequenceContext,controller,interface,
                                         converted,ScanMultipleBridge::NativeSize);
    }
    if (api_.prepareAssociation) {
        const int prepared=api_.prepareAssociation(api_.sequenceContext,interface);
        if (prepared) return prepared;
    }
    CopyInScope scope;
    scope.thread=api_.currentThread();scope.caller=api_.singleCopyInCaller;
    scope.controller=controller;scope.source=request->userData;
    scope.bytes=converted;scope.size=Single::ElCapSize;
    if (!multipleRegistry_.add(scope)) return EBUSY;
    {
        RequestLength narrowed(*request,Single::ElCapSize);
        error=api_.setScanRequest(controller,interface,virtualInterface,request,user64);
    }
    multipleRegistry_.remove(scope);
    if (!error && !scope.consumed) return EIO;
    return error;
}

int Runtime::setScanRequestMultiple(void *controller, void *interface, void *virtualInterface,
                                    Request *request, bool user64) {
    RequestGuard guard(requestRegistry_,interface,ready());
    if (!guard.admitted) return EBUSY;
    if (!request || request->type != 86)
        return original(api_.setScanRequestMultiple, controller, interface, virtualInterface,
                        request, user64);

    // Keep the exact ElCap ABI available to legacy callers. Other oversized
    // buffers must never reach its fixed 0x908-byte copyIn site, where a newer
    // producer could otherwise be silently truncated.
    if (request->length == ScanMultipleBridge::ElCapSize) {
        return dispatchExactLegacy(api_.setScanRequestMultiple,controller,interface,
                                   virtualInterface,request,user64);
    }
    ScanMultipleBridge::NativeLayout layout;
    if (!ScanMultipleBridge::nativeLayoutForSize(request->length,layout))
        return request->length > ScanMultipleBridge::ElCapSize ? EOPNOTSUPP : EINVAL;

    if (!user64 || !request->userData || request->value || request->padding) return EINVAL;
    if (virtualInterface || !isPrimary(controller, interface, request)) return EOPNOTSUPP;
    if (!ready()) return ENXIO;

    ScanBuffer buffer(api_,request->length);
    if (!buffer.bytes) return ENOMEM;
    uint8_t *native = buffer.bytes;
    uint8_t *projected = buffer.bytes + request->length;
    int error = api_.copyIn(controller, request->userData, native,
                            request->length);
    if (error) return error;
    const auto shape=ScanMultipleBridge::validateNativeShape(native,request->length);
    if (shape.error) return shape.error;
    if (!isPrimary(controller, interface, request)) return ESTALE;
    const bool cacheOnly=ScanCompat::read32(native+ScanMultipleBridge::NativeScanType)==3;
    if (!cacheOnly && (!api_.supportsMultiple || !api_.supportsMultiple(controller,interface)))
        return api_.submitSingleSequence?
            api_.submitSingleSequence(api_.sequenceContext,controller,interface,native,request->length):
            EOPNOTSUPP;

    const auto converted = ScanMultipleBridge::convertToElCap(
        native, request->length, projected, ScanMultipleBridge::ElCapSize);
    if (converted.error) return converted.error;
    return dispatchProjectedMultiple(controller,interface,virtualInterface,
                                      request,user64,projected);
}

int Runtime::dispatchProjectedMultiple(void *controller,void *interface,
                                        void *virtualInterface,Request *request,
                                        bool user64,const uint8_t *projected) {
    // FAST requests query the manager cache without starting a chipset scan.
    // Invalidate an idle managed result set, or reject overlap with its owner.
    if (api_.prepareAssociation) {
        const int prepared=api_.prepareAssociation(api_.sequenceContext,interface);
        if (prepared) return prepared;
    }

    CopyInScope scope;
    scope.thread = api_.currentThread();
    scope.caller = api_.multipleCopyInCaller;
    scope.controller = controller;
    scope.source = request->userData;
    scope.bytes = projected;
    scope.size = ScanMultipleBridge::ElCapSize;
    if (!multipleRegistry_.add(scope)) return EBUSY;

    {
        RequestLength narrowed(*request, ScanMultipleBridge::ElCapSize);
        const int error = api_.setScanRequestMultiple(controller, interface, virtualInterface, request, user64);
        multipleRegistry_.remove(scope);
        if (!error && !scope.consumed) return EIO;
        return error;
    }
}

int Runtime::copyIn(void *controller, uint64_t source, void *destination, size_t size,
                    uintptr_t caller) {
    if (!api_.copyIn) return ENXIO;
    if (!api_.currentThread) return api_.copyIn(controller, source, destination, size);
    const uintptr_t thread = api_.currentThread();

    if (multipleRegistry_.lock.value && multipleRegistry_.lock.enter && multipleRegistry_.lock.leave) {
        multipleRegistry_.lock.enter(multipleRegistry_.lock.value);
        bool pending = false;
        for (auto *scope = multipleRegistry_.head; scope; scope = scope->next)
            if (scope->thread == thread) { pending = true; break; }
        multipleRegistry_.lock.leave(multipleRegistry_.lock.value);
        if (pending) {
            const int consumed = multipleRegistry_.consume(thread, caller, controller,
                                                            source, destination, size);
            return consumed == -1 ? EINVAL : consumed;
        }
    }

    if (associationRegistry_.lock.value && associationRegistry_.lock.enter &&
        associationRegistry_.lock.leave) {
        associationRegistry_.lock.enter(associationRegistry_.lock.value);
        bool pending = false;
        bool rightCaller = false;
        for (auto *scope = associationRegistry_.head; scope; scope = scope->next) {
            if (scope->thread == thread) {
                pending = true;
                rightCaller = scope->caller == caller;
                break;
            }
        }
        associationRegistry_.lock.leave(associationRegistry_.lock.value);
        if (pending) {
            if (!rightCaller) return EINVAL;
            const int consumed = associationRegistry_.consume(
                thread, caller, controller, source, destination, size);
            return consumed == -1 ? EINVAL : consumed;
        }
    }
    return api_.copyIn(controller, source, destination, size);
}

int Runtime::copyOut(void *controller, const void *source, uint64_t destination, size_t size,
                     uintptr_t caller) {
    if (!api_.copyOut) return ENXIO;
    if (ready() && api_.currentThread) {
        size_t captured=0;
        const int get48=getAPIEListCopyOutRegistry_.capture(api_.currentThread(),caller,
            controller,destination,source,size,&captured);
        if (get48>=0) return get48;

        uint8_t *modified = nullptr;
        const int leased = capabilityCopyOutRegistry_.prepare(
            api_.currentThread(), controller, destination, source, size, &modified);
        if (leased >= 0) {
            if (leased) return leased;
            return api_.copyOut(controller, modified, destination, size);
        }
    }
    return api_.copyOut(controller, source, destination, size);
}

} // namespace LegacyBridge
} // namespace LegacyWiFi
