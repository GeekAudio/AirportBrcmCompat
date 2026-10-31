// Admission/lifetime only. No IOKit or authorization; storage stays resident.
#ifndef AIRPORT_AWDL_EVENT_PIPE_CORE_HPP
#define AIRPORT_AWDL_EVENT_PIPE_CORE_HPP
#include <stdint.h>
namespace AWDLKernel {
class EventPipeCore final {
public:
    enum class Phase : uint32_t { Empty, Preparing, Open, Closing, Closed };
    static constexpr uint32_t MaximumOperations=65535;
private:
    static constexpr uint32_t PhaseMask=7, Creating=8, Finishing=16, One=256;
    uint32_t state=0;
public:
    EventPipeCore()=default;
    EventPipeCore(const EventPipeCore &)=delete;
    EventPipeCore &operator=(const EventPipeCore &)=delete;
    Phase phase() const {
        return static_cast<Phase>(__atomic_load_n(&state,__ATOMIC_ACQUIRE)&PhaseMask);
    }
    uint32_t operations() const {return __atomic_load_n(&state,__ATOMIC_ACQUIRE)/One;}
    bool beginCreate() {
        uint32_t expected=0;
        return __atomic_compare_exchange_n(&state,&expected,
            static_cast<uint32_t>(Phase::Preparing)|Creating,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    }
    // All initialized members are published before dropping Creating. A close
    // racing allocation can mark Closing, but can never claim its resources.
    bool finishCreate(bool success) {
        auto value=__atomic_load_n(&state,__ATOMIC_ACQUIRE);
        for (;;) {
            if (!(value&Creating)) return false;
            const auto p=static_cast<Phase>(value&PhaseMask);
            if (p!=Phase::Preparing && p!=Phase::Closing) return false;
            const auto next=(value&~(PhaseMask|Creating))|
                static_cast<uint32_t>(success && p==Phase::Preparing?Phase::Open:Phase::Closing);
            if (__atomic_compare_exchange_n(&state,&value,next,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
                return (next&PhaseMask)==static_cast<uint32_t>(Phase::Open);
        }
    }
    bool acquire() {
        auto value=__atomic_load_n(&state,__ATOMIC_ACQUIRE);
        for (;;) {
            if ((value&PhaseMask)!=static_cast<uint32_t>(Phase::Open) || value/One==MaximumOperations)
                return false;
            if (__atomic_compare_exchange_n(&state,&value,value+One,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
                return true;
        }
    }
    bool release() {
        auto value=__atomic_load_n(&state,__ATOMIC_ACQUIRE);
        for (;;) {
            if (value/One==0) return false;
            if (__atomic_compare_exchange_n(&state,&value,value-One,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE))
                return true;
        }
    }
    void beginClose() {
        auto value=__atomic_load_n(&state,__ATOMIC_ACQUIRE);
        for (;;) {
            const auto p=static_cast<Phase>(value&PhaseMask);
            if (p==Phase::Closing || p==Phase::Closed) return;
            const auto next=(value&~PhaseMask)|static_cast<uint32_t>(
                p==Phase::Empty?Phase::Closed:Phase::Closing);
            if (__atomic_compare_exchange_n(&state,&value,next,false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE)) return;
        }
    }
    // The winner alone may destroy descriptors/drop references. Busy never
    // waits or changes a generation. After Closed this storage is not reused.
    bool acquireCloser() {
        uint32_t expected=static_cast<uint32_t>(Phase::Closing);
        return __atomic_compare_exchange_n(&state,&expected,expected|Finishing,
            false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    }
    bool finishClose(bool success) {
        uint32_t expected=static_cast<uint32_t>(Phase::Closing)|Finishing;
        return __atomic_compare_exchange_n(&state,&expected,
            static_cast<uint32_t>(success?Phase::Closed:Phase::Closing),
            false,__ATOMIC_ACQ_REL,__ATOMIC_ACQUIRE);
    }
};
}
#endif
