// Portable, allocation-free state for observing child BSS memory mutations.
// The caller must serialize every State/Ticket method with the same short lock.
#ifndef AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_MEMORY_HPP
#define AIRPORT_BRCM_LEGACY_WIFI_DISASSOCIATE_MEMORY_HPP

#include <stdint.h>

namespace LegacyWiFi { namespace DisassociateMemory {

class State;

class Ticket {
public:
    Ticket() = default;
    Ticket(const Ticket &) = delete;
    Ticket &operator=(const Ticket &) = delete;
    Ticket(Ticket &&) = delete;
    Ticket &operator=(Ticket &&) = delete;

    bool active() const { return active_; }
    const State *owner() const { return owner_; }

private:
    friend class State;

    State *owner_ = nullptr;
    bool active_ = false;
    bool selected_ = false;
    uint64_t exclusiveEpoch_ = 0;
};

class State {
public:
    State() = default;
    State(const State &) = delete;
    State &operator=(const State &) = delete;
    State(State &&) = delete;
    State &operator=(State &&) = delete;

    // Returns a snapshot generation only while no writer is active.
    // Zero is permanently reserved for poisoned/unavailable state.
    uint64_t snapshotEpoch() const {
        return !poisoned_ && writers_ == 0 && epoch_ != 0 ? epoch_ : 0;
    }

    bool readable(uint64_t expectedEpoch) const {
        return expectedEpoch != 0 && !poisoned_ && writers_ == 0 &&
            epoch_ == expectedEpoch;
    }

    // A selected operation is the outer SET22 observation. Its registration
    // itself does not change the epoch; it makes ordinary snapshots unreadable
    // until the ticket is ended.
    bool beginSelected(uint64_t expectedEpoch, uintptr_t thread, Ticket &ticket) {
        if (!ticketAvailable(ticket) || thread == 0 || !readable(expectedEpoch) ||
            selectedTicket_ != nullptr || writers_ == UINT32_MAX) return false;
        ++writers_;
        selectedThread_ = thread;
        selectedTicket_ = &ticket;
        ticket.owner_ = this;
        ticket.active_ = true;
        ticket.selected_ = true;
        return true;
    }

    // Every accepted mutation holds one writer ticket. Only an explicitly
    // identified nested clear on the selected thread is part of the selected
    // operation and preserves its epoch. All other mutations invalidate it.
    bool beginMutation(uintptr_t thread, bool nestedClear, Ticket &ticket) {
        if (!ticketAvailable(ticket) || poisoned_ || epoch_ == 0) return false;
        if (writers_ == UINT32_MAX) {
            poison();
            return false;
        }

        const bool selectedNestedClear = nestedClear && thread != 0 &&
            thread == selectedThread_ && selectedTicket_ &&
            selectedTicket_->owner_ == this && selectedTicket_->active_ &&
            selectedTicket_->selected_;
        if (!selectedNestedClear) {
            if (epoch_ == UINT64_MAX) {
                poison();
                return false;
            }
            ++epoch_;
        }

        const uint64_t exclusiveEpoch = writers_ == 0 && !selectedTicket_ ? epoch_ : 0;
        ++writers_;
        ticket.owner_ = this;
        ticket.active_ = true;
        ticket.selected_ = false;
        ticket.exclusiveEpoch_ = exclusiveEpoch;
        return true;
    }

    // A writer may inspect its own before/after state only when it started
    // alone and no other mutation has entered since. A writer that overlapped
    // at entry never becomes eligible merely because the other writer ended.
    // Call only at the wrapper's boundaries, while holding the shared lock;
    // this does not authorize reads during the native mutation body or confer
    // lifetime on native objects. Publish any owned result and end the ticket
    // in the same critical section; a later ordinary snapshotEpoch() could
    // otherwise stamp old data with a newer generation. Zero forbids publication.
    uint64_t mutationEpoch(const Ticket &ticket) const {
        return !poisoned_ && writers_ == 1 && !selectedTicket_ &&
            ticket.owner_ == this && ticket.active_ && !ticket.selected_ &&
            ticket.exclusiveEpoch_ != 0 && ticket.exclusiveEpoch_ == epoch_
            ? epoch_ : 0;
    }

    bool selectedReadable(const Ticket &ticket, uint64_t expectedEpoch) const {
        return expectedEpoch != 0 && !poisoned_ && epoch_ == expectedEpoch &&
            writers_ == 1 && ticket.owner_ == this && ticket.active_ &&
            ticket.selected_ && selectedTicket_ == &ticket &&
            selectedThread_ != 0;
    }

    // Returns false for a foreign or already-ended ticket. Ending a selected
    // ticket clears its selected-thread exemption even when other writers
    // remain active.
    bool end(Ticket &ticket) {
        if (ticket.owner_ != this || !ticket.active_) return false;
        if (writers_ == 0) {
            poison();
            clearTicket(ticket);
            return false;
        }

        if (ticket.selected_) {
            if (selectedTicket_ != &ticket || selectedThread_ == 0) {
                poison();
            }
            if (selectedTicket_ == &ticket) selectedTicket_ = nullptr;
            selectedThread_ = 0;
        }
        --writers_;
        clearTicket(ticket);
        return true;
    }

private:
    // Test-only access permits deterministic counter/epoch overflow coverage
    // without exposing an initializer that could re-enable a poisoned state.
    friend struct TestAccess;

    static bool ticketAvailable(const Ticket &ticket) {
        return !ticket.owner_ && !ticket.active_ && !ticket.selected_ &&
            ticket.exclusiveEpoch_ == 0;
    }

    void clearTicket(Ticket &ticket) {
        ticket.owner_ = nullptr;
        ticket.active_ = false;
        ticket.selected_ = false;
        ticket.exclusiveEpoch_ = 0;
    }

    void poison() {
        poisoned_ = true;
        epoch_ = 0;
    }

    uint64_t epoch_ = 1;
    uint32_t writers_ = 0;
    uintptr_t selectedThread_ = 0;
    Ticket *selectedTicket_ = nullptr;
    bool poisoned_ = false;
};

} } // namespace LegacyWiFi::DisassociateMemory

#endif
