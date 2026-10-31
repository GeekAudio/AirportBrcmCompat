// Retained, exact primary-interface bindings for scan-event routing. The
// interrupt-side lookup only compares pointers and copies a cached BSD name;
// all IOKit queries and notifier setup happen from the sleepable GET12 path.
// Retired slots are never reused during this kext lifetime: retained objects
// prevent a late old callback from aliasing a newly created interface address.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_EVENT_BINDING_REGISTRY_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_EVENT_BINDING_REGISTRY_HPP

#include "event_contracts.hpp"
#include "event_binding_state.hpp"
#include "provider_contract.hpp"
#include "../scan_kernel/primary_interface_iokit.hpp"
#include <IOKit/IOMessage.h>
#include <IOKit/IONotifier.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLocks.h>
#include <IOKit/IOWorkLoop.h>
#include <machine/machine_routines.h>
#include <string.h>

namespace LegacyWiFi {
namespace EventContracts {

class InterfaceBindingRegistry {
public:
    static constexpr size_t Capacity = 8;

    bool initialize() {
        if (lock_) return true;
        IOSimpleLock *created = IOSimpleLockAlloc();
        if (!created) return false;
        lock_ = created;
        return true;
    }

    // Bind the interface only after GET12 has already been validated as a
    // primary request. This is deliberately limited to ordinary enabled-
    // interrupt WorkLoop context because property access and registerInterest
    // may allocate or block.
    bool bind(IOService *controller, IOService *interface, DriverKind kind) {
        if (!controller || !interface || !lock_ || ml_at_interrupt_context() ||
            !ml_get_interrupts_enabled() ||
            static_cast<uint8_t>(kind) > static_cast<uint8_t>(DriverKind::Broadcom43224))
            return false;

        IOWorkLoop *loop = controller->getWorkLoop();
        if (!loop || !loop->inGate() || interface->getWorkLoop() != loop ||
            controller->isInactive() || interface->isInactive() ||
            interface->getProvider() != controller ||
            !PrimaryInterface::exactClass(controller, controllerClassName(kind)) ||
            !PrimaryInterface::exactClass(interface, interfaceClassName(kind)) ||
            !controller->getMetaClass() || !interface->getMetaClass() ||
            interface->getMetaClass()->getClassSize() < MinimumInterfaceObjectSize)
            return false;

        PrimaryInterface::BSDNameProperty name;
        if (!PrimaryInterface::copyBSDName(interface, name) ||
            name.length == 0 || name.length >= InterfaceNameSize) return false;

        // Existing exact binding is idempotent. A competing family, creating
        // slot, or different controller for this object is rejected. Retired
        // slots remain occupied to preserve pointer identity against late work.
        for (;;) {
            size_t emptyIndex = Capacity;
            bool nameConflict = false;
            LockGuard guard(lock_);
            for (size_t index = 0; index < Capacity; ++index) {
                Slot &slot = slots_[index];
                if ((slot.state == BindingState::Creating ||
                     slot.state == BindingState::AbortRequested ||
                     slot.state == BindingState::Active) &&
                    slot.interface != interface && sameName(slot.bsdName, name.bytes))
                    nameConflict = true;
                if (slot.interface == interface && slot.state != BindingState::Empty) {
                    if (slot.state == BindingState::Active && slot.controller == controller &&
                        slot.kind == kind && sameName(slot.bsdName, name.bytes)) {
                        return true;
                    }
                    return false;
                }
                if (bindingSlotAvailable(slot.state) && emptyIndex == Capacity)
                    emptyIndex = index;
            }
            if (nameConflict || emptyIndex == Capacity) return false;
            Slot &slot = slots_[emptyIndex];
            slot.state = BindingState::Creating;
            slot.controller = controller;
            slot.interface = interface;
            slot.kind = kind;
            memcpy(slot.bsdName, name.bytes, sizeof(slot.bsdName));
            guard.unlock();

            // Keep addresses stable across notifier callbacks and stale event
            // delivery for the lifetime of this kext.
            controller->retain();
            interface->retain();
            IONotifier *controllerInterest = controller->registerInterest(
                gIOGeneralInterest, serviceInterest, this, &slot);
            IONotifier *interfaceInterest = interface->registerInterest(
                gIOGeneralInterest, serviceInterest, this, &slot);

            const bool stillSameService = controllerInterest && interfaceInterest &&
                !controller->isInactive() && !interface->isInactive() &&
                interface->getProvider() == controller &&
                interface->getWorkLoop() == loop && loop->inGate();
            guard.lock();
            slot.controllerInterest = controllerInterest;
            slot.interfaceInterest = interfaceInterest;
            slot.state = bindingCreationFinished(slot.state, stillSameService);
            const bool active = slot.state == BindingState::Active;
            guard.unlock();
            return active;
        }
    }

    // Safe in interrupt context: no virtual IOKit calls, allocation, or
    // property reads; retained service pointers cannot be reused as addresses.
    bool lookup(void *interface, DriverKind kind,
                char output[InterfaceNameSize]) const {
        if (!lock_ || !interface || !output) return false;
        bool found = false;
        const IOInterruptState restore = IOSimpleLockLockDisableInterrupt(lock_);
        for (size_t index = 0; index < Capacity; ++index) {
            const Slot &slot = slots_[index];
            if (slot.state != BindingState::Active || slot.interface != interface ||
                slot.kind != kind) continue;
            memcpy(output, slot.bsdName, InterfaceNameSize);
            found = true;
            break;
        }
        IOSimpleLockUnlockEnableInterrupt(lock_, restore);
        return found;
    }

private:
    static constexpr size_t MinimumInterfaceObjectSize =
        ProviderContract::InterfaceScanManagerOffset + sizeof(void *);

    struct Slot {
        BindingState state = BindingState::Empty;
        DriverKind kind = DriverKind::Broadcom4331;
        IOService *controller = nullptr;
        IOService *interface = nullptr;
        IONotifier *controllerInterest = nullptr;
        IONotifier *interfaceInterest = nullptr;
        char bsdName[InterfaceNameSize] {};
    };

    IOSimpleLock *lock_ = nullptr;
    Slot slots_[Capacity] {};

    class LockGuard {
    public:
        explicit LockGuard(IOSimpleLock *value) : lock_(value) { lock(); }
        ~LockGuard() { unlock(); }
        void unlock() {
            if (!locked_) return;
            IOSimpleLockUnlockEnableInterrupt(lock_, restore_);
            locked_ = false;
        }
        void lock() {
            if (locked_) return;
            restore_ = IOSimpleLockLockDisableInterrupt(lock_);
            locked_ = true;
        }
    private:
        IOSimpleLock *lock_;
        IOInterruptState restore_ = 0;
        bool locked_ = false;
    };

    static bool sameName(const char *left, const char *right) {
        for (size_t index = 0; index < InterfaceNameSize; ++index) {
            if (left[index] != right[index]) return false;
            if (left[index] == '\0') return true;
        }
        return false;
    }

    static IOReturn serviceInterest(void *target, void *refCon,
                                    UInt32 messageType, IOService *service,
                                    void *, vm_size_t) {
        auto *registry = static_cast<InterfaceBindingRegistry *>(target);
        auto *slot = static_cast<Slot *>(refCon);
        if (!registry || !registry->lock_ || !slot ||
            messageType != kIOMessageServiceIsTerminated) return kIOReturnSuccess;
        const IOInterruptState restore = IOSimpleLockLockDisableInterrupt(registry->lock_);
        if (slot->state == BindingState::Creating || slot->state == BindingState::Active) {
            if (slot->controller == service || slot->interface == service)
                slot->state = bindingTerminationRequested(slot->state);
        }
        IOSimpleLockUnlockEnableInterrupt(registry->lock_, restore);
        return kIOReturnSuccess;
    }
};

} // namespace EventContracts
} // namespace LegacyWiFi

#endif
