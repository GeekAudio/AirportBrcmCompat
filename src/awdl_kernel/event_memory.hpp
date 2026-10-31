#ifndef AIRPORT_BRCM_AWDL_EVENT_MEMORY_HPP
#define AIRPORT_BRCM_AWDL_EVENT_MEMORY_HPP

#include <IOKit/IOBufferMemoryDescriptor.h>
#include "../awdl_compat/event_ring.h"

namespace AWDLKernel {

/* Allocation/descriptor ownership only; not an IOUserClient or a ready backend.
 * All calls (including destruction) require one real caller-owned serial context.
 * create can block: never invoke it in an interrupt or under a simple lock.
 * The caller must quiesce publishers before destroy, and separately enforce
 * task/provider entitlement, map admission, async ownership and teardown.
 */
class EventMemory final {
public:
    enum : uint32_t {
        RingMemoryType = 1,
        StateMemoryType = 2,
        DefaultRingCapacity = AWC_RING_PAGE * 2,
        MaximumRingCapacity = 1024 * 1024 // Component allocation bound, not a native ABI claim.
    };

    EventMemory() = default;
    ~EventMemory();
    EventMemory(const EventMemory &) = delete;
    EventMemory &operator=(const EventMemory &) = delete;

    IOReturn create(uint32_t ringCapacity = DefaultRingCapacity);
    void destroy();

    /* clientMemoryForType-compatible result: success transfers one retained
     * descriptor reference to the caller/IOKit, never a borrowed pointer.
     * options is output: type1 forces ReadOnly; type2 permits read/write.
     * This does not create a mapping or authorize the requesting task.
     */
    IOReturn retainMemoryForType(uint32_t type, IOOptionBits *options,
                                IOMemoryDescriptor **memory) const;

    /* No schema selection, capture, callback, or Mach notification. Producer
     * cursor remains in this private object, not in user-writable state.
     * Outputs are usable only according to awc_ring_publish's return contract.
     */
    awc_ring_error publish(const awc_event_metadata *metadata, const void *body,
                           size_t length, awc_ring_notice *notice);

    bool hasAllocation() const { return ringMemory_ && stateMemory_; }

private:
    IOBufferMemoryDescriptor *ringMemory_ {nullptr};
    IOBufferMemoryDescriptor *stateMemory_ {nullptr};
    awc_ring ring_ {};
};

} // namespace AWDLKernel
#endif
