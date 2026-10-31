#include "event_memory.hpp"
#include <kern/task.h>
#include <string.h>

#if !defined(__x86_64__)
#error "The pinned native event ABI and 4096-byte page isolation are x86_64 only"
#endif

namespace AWDLKernel {

static_assert(sizeof(awc_ring_shared) == 12, "Native state wire length");
static_assert((kIOMapReadOnly & kIOMapUserOptionsMask) == 0,
              "User map flags must not remove the ring ReadOnly constraint");

EventMemory::~EventMemory() { destroy(); }

IOReturn EventMemory::create(uint32_t capacity) {
    if (ringMemory_ || stateMemory_) return kIOReturnBusy;
    if (capacity < DefaultRingCapacity || capacity > MaximumRingCapacity ||
        capacity % AWC_RING_PAGE) return kIOReturnBadArgument;

    const IOOptionBits allocationOptions = kIOMemoryKernelUserShared | kIODirectionInOut;
    IOBufferMemoryDescriptor *ring = IOBufferMemoryDescriptor::inTaskWithOptions(
        kernel_task, allocationOptions, capacity, AWC_RING_PAGE);
    if (!ring) return kIOReturnNoMemory;
    // The 12-byte logical state gets a dedicated complete page. A user mapping
    // can expose page rounding; no adjacent kernel allocation may share it.
    IOBufferMemoryDescriptor *state = IOBufferMemoryDescriptor::inTaskWithOptions(
        kernel_task, allocationOptions, AWC_RING_PAGE, AWC_RING_PAGE);
    if (!state) { ring->release(); return kIOReturnNoMemory; }

    void *ringBytes = ring->getBytesNoCopy();
    void *stateBytes = state->getBytesNoCopy();
    bool valid = ring->getCapacity() == capacity && ring->getLength() == capacity &&
        state->getCapacity() == AWC_RING_PAGE && state->getLength() == AWC_RING_PAGE &&
        ringBytes && stateBytes &&
        !(reinterpret_cast<uintptr_t>(ringBytes) % AWC_RING_PAGE) &&
        !(reinterpret_cast<uintptr_t>(stateBytes) % AWC_RING_PAGE);
    if (!valid) { state->release(); ring->release(); return kIOReturnError; }

    // Do not rely on an allocator's incidental zero-fill behavior. Clear full
    // allocated pages before shrinking state to its 12-byte protocol length.
    memset(ringBytes, 0, capacity);
    memset(stateBytes, 0, AWC_RING_PAGE);
    state->setLength(sizeof(awc_ring_shared));
    if (state->getLength() != sizeof(awc_ring_shared) ||
        awc_ring_init(&ring_, ringBytes, capacity,
            static_cast<awc_ring_shared *>(stateBytes), sizeof(awc_ring_shared)) != AWC_RING_OK) {
        ring_ = {};
        state->release(); ring->release();
        return kIOReturnError;
    }
    // Publish both owner references only after the complete object is valid.
    ringMemory_ = ring;
    stateMemory_ = state;
    return kIOReturnSuccess;
}

void EventMemory::destroy() {
    // Caller must have stopped publishers. Do not forcibly unmap, clear shared
    // pages under an existing reader, or reuse storage retained by a mapping.
    IOBufferMemoryDescriptor *ring = ringMemory_;
    IOBufferMemoryDescriptor *state = stateMemory_;
    ringMemory_ = nullptr;
    stateMemory_ = nullptr;
    ring_ = {};
    if (state) state->release();
    if (ring) ring->release();
}

IOReturn EventMemory::retainMemoryForType(uint32_t type, IOOptionBits *options,
                                         IOMemoryDescriptor **memory) const {
    if (options) *options = 0;
    if (memory) *memory = nullptr;
    if (!options || !memory) return kIOReturnBadArgument;
    if (type != RingMemoryType && type != StateMemoryType) return kIOReturnUnsupported;
    if (!hasAllocation()) return kIOReturnNotOpen;
    IOMemoryDescriptor *descriptor = type == RingMemoryType ? ringMemory_ : stateMemory_;
    descriptor->retain();
    *options = type == RingMemoryType ? kIOMapReadOnly : 0;
    *memory = descriptor;
    return kIOReturnSuccess;
}

awc_ring_error EventMemory::publish(const awc_event_metadata *metadata, const void *body,
                                    size_t length, awc_ring_notice *notice) {
    if (!hasAllocation()) return AWC_RING_CLOSED;
    return awc_ring_publish(&ring_, metadata, body, length, notice);
}

} // namespace AWDLKernel
