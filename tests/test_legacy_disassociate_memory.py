"""Sanitizer-backed lifecycle tests for the portable disassociate-memory core."""
from pathlib import Path
import subprocess
import tempfile
import unittest


PROJECT = Path(__file__).resolve().parents[1]
HARNESS = r'''
#include "legacy_wifi_compat/disassociate_memory.hpp"

#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <type_traits>

namespace M = LegacyWiFi::DisassociateMemory;

namespace LegacyWiFi { namespace DisassociateMemory {
struct TestAccess {
    static void setEpoch(State &state, uint64_t epoch) {
        state.epoch_ = epoch;
        state.poisoned_ = epoch == 0;
    }
    static void setWriters(State &state, uint32_t writers) {
        state.writers_ = writers;
    }
    static bool poisoned(const State &state) { return state.poisoned_; }
};
} }

static_assert(!std::is_copy_constructible<M::State>::value, "State cannot be copied");
static_assert(!std::is_copy_assignable<M::State>::value, "State cannot be copy-assigned");
static_assert(!std::is_move_constructible<M::State>::value, "State cannot be moved");
static_assert(!std::is_move_assignable<M::State>::value, "State cannot be move-assigned");
static_assert(!std::is_copy_constructible<M::Ticket>::value, "Ticket cannot be copied");
static_assert(!std::is_copy_assignable<M::Ticket>::value, "Ticket cannot be copy-assigned");
static_assert(!std::is_move_constructible<M::Ticket>::value, "Ticket cannot be moved");
static_assert(!std::is_move_assignable<M::Ticket>::value, "Ticket cannot be move-assigned");

static void test_initial_snapshot_and_selected_ticket() {
    M::State state;
    M::Ticket selected;
    const uint64_t epoch = state.snapshotEpoch();
    assert(epoch == 1 && state.readable(epoch));
    assert(!state.readable(0));
    assert(!state.beginSelected(epoch, 0, selected));
    assert(state.beginSelected(epoch, 11, selected));
    assert(selected.active() && selected.owner() == &state);
    assert(state.snapshotEpoch() == 0 && !state.readable(epoch));
    assert(state.selectedReadable(selected, epoch));

    M::Ticket nestedClear;
    assert(state.beginMutation(11, true, nestedClear));
    assert(nestedClear.active() && nestedClear.owner() == &state);
    assert(!state.selectedReadable(selected, epoch)); // Two live writers.
    assert(state.end(nestedClear));
    assert(!nestedClear.active() && nestedClear.owner() == nullptr);
    assert(state.selectedReadable(selected, epoch)); // Nested clear kept epoch.
    assert(state.end(selected));
    assert(!selected.active() && selected.owner() == nullptr);
    assert(state.snapshotEpoch() == epoch && state.readable(epoch));
}

static void test_only_nested_clear_on_selected_thread_preserves_epoch() {
    M::State state;
    M::Ticket selected;
    const uint64_t epoch = state.snapshotEpoch();
    assert(state.beginSelected(epoch, 21, selected));

    M::Ticket wrongThreadClear;
    assert(state.beginMutation(22, true, wrongThreadClear));
    assert(!state.selectedReadable(selected, epoch));
    assert(state.end(wrongThreadClear));
    assert(!state.readable(epoch)); // Completion does not restore an old epoch.
    assert(!state.selectedReadable(selected, epoch));

    assert(state.end(selected));
    assert(state.snapshotEpoch() == epoch + 1);
    assert(state.readable(epoch + 1));

    // A same-thread ordinary mutation still invalidates; the exemption is
    // reserved for an explicitly identified nested cache clear.
    M::State second;
    M::Ticket selected2, ordinary;
    const uint64_t epoch2 = second.snapshotEpoch();
    assert(second.beginSelected(epoch2, 21, selected2));
    assert(second.beginMutation(21, false, ordinary));
    assert(!second.selectedReadable(selected2, epoch2));
    assert(second.end(ordinary));
    assert(second.end(selected2));
    assert(second.snapshotEpoch() == epoch2 + 1);
}

static void test_foreign_writer_during_selected_operation() {
    M::State state;
    M::Ticket selected, foreign;
    const uint64_t epoch = state.snapshotEpoch();
    assert(state.beginSelected(epoch, 31, selected));
    assert(state.beginMutation(32, false, foreign));
    assert(!state.selectedReadable(selected, epoch));
    assert(state.end(foreign));
    assert(!state.readable(epoch));
    assert(state.end(selected));
    assert(state.snapshotEpoch() == epoch + 1);
    assert(state.readable(epoch + 1));

    // Ending the selected scope while a foreign writer is still active drops
    // only its own count and removes the nested-clear exemption.
    M::State overlapping;
    M::Ticket selected2, foreign2, nowOrdinary;
    const uint64_t epoch2 = overlapping.snapshotEpoch();
    assert(overlapping.beginSelected(epoch2, 33, selected2));
    assert(overlapping.beginMutation(34, false, foreign2));
    assert(overlapping.end(selected2));
    assert(overlapping.snapshotEpoch() == 0);
    assert(overlapping.beginMutation(33, true, nowOrdinary));
    assert(overlapping.end(foreign2));
    assert(overlapping.snapshotEpoch() == 0);
    assert(overlapping.end(nowOrdinary));
    assert(overlapping.snapshotEpoch() == epoch2 + 2);
}

static void test_multiple_writers_and_new_snapshot() {
    M::State state;
    M::Ticket first, second;
    const uint64_t initial = state.snapshotEpoch();
    assert(state.beginMutation(41, false, first));
    assert(state.snapshotEpoch() == 0);
    assert(state.beginMutation(42, false, second));
    assert(state.snapshotEpoch() == 0);
    assert(!state.readable(initial));
    assert(state.end(first));
    assert(state.snapshotEpoch() == 0);
    assert(state.end(second));
    const uint64_t after = state.snapshotEpoch();
    assert(after == initial + 2 && state.readable(after));
}

static void test_wrong_duplicate_and_reused_tickets() {
    M::State owner, other;
    M::Ticket ticket, foreignTicket;
    const uint64_t epoch = owner.snapshotEpoch();
    assert(owner.beginSelected(epoch, 51, ticket));
    assert(!other.end(ticket));
    assert(owner.selectedReadable(ticket, epoch));
    assert(!owner.beginMutation(51, true, ticket)); // Active ticket cannot be reused.
    assert(owner.end(ticket));
    assert(!owner.end(ticket));
    assert(owner.readable(epoch));

    const uint64_t otherEpoch = other.snapshotEpoch();
    assert(other.beginMutation(52, false, foreignTicket));
    assert(!owner.end(foreignTicket));
    assert(other.snapshotEpoch() == 0);
    assert(other.end(foreignTicket));
    assert(other.snapshotEpoch() == otherEpoch + 1);
    assert(!foreignTicket.active() && foreignTicket.owner() == nullptr);
}

static void test_epoch_overflow_permanently_poisons() {
    M::State state;
    M::Ticket ticket;
    M::TestAccess::setEpoch(state, std::numeric_limits<uint64_t>::max());
    assert(!state.beginMutation(61, false, ticket));
    assert(M::TestAccess::poisoned(state));
    assert(state.snapshotEpoch() == 0 && !state.readable(1));
    assert(!state.beginSelected(std::numeric_limits<uint64_t>::max(), 61, ticket));
    assert(!state.beginMutation(61, true, ticket));

    // Overflow during a selected operation poisons the state, but the already
    // registered selected ticket can still be ended without wrapping counts.
    M::State selectedState;
    M::Ticket selected, overflowing;
    M::TestAccess::setEpoch(selectedState, std::numeric_limits<uint64_t>::max());
    assert(selectedState.beginSelected(std::numeric_limits<uint64_t>::max(), 62, selected));
    assert(!selectedState.beginMutation(63, false, overflowing));
    assert(M::TestAccess::poisoned(selectedState));
    assert(!selectedState.selectedReadable(selected, std::numeric_limits<uint64_t>::max()));
    assert(selectedState.end(selected));
    assert(selectedState.snapshotEpoch() == 0);
}

static void test_writer_count_overflow_permanently_poisons() {
    M::State state;
    M::Ticket ticket;
    M::TestAccess::setWriters(state, std::numeric_limits<uint32_t>::max());
    assert(!state.beginMutation(71, false, ticket));
    assert(M::TestAccess::poisoned(state));
    assert(state.snapshotEpoch() == 0 && !state.readable(1));
    assert(!state.beginSelected(1, 71, ticket));
    assert(!state.beginMutation(71, false, ticket));
}

static void test_exclusive_mutation_publication_epoch() {
    M::State state, other;
    M::Ticket ticket, unstarted;
    assert(!state.mutationEpoch(ticket));
    assert(state.beginMutation(81, false, ticket));
    const uint64_t publication = state.mutationEpoch(ticket);
    assert(publication == 2);
    assert(!state.snapshotEpoch());
    assert(!state.mutationEpoch(unstarted));
    assert(!other.mutationEpoch(ticket));
    assert(!other.end(ticket));
    assert(state.mutationEpoch(ticket) == publication);
    assert(state.end(ticket));
    assert(!state.mutationEpoch(ticket));
    assert(state.snapshotEpoch() == publication);

    // Reusing an ended ticket represents a new generation, not the old
    // publication. The saved generation no longer admits a read.
    assert(state.beginMutation(81, false, ticket));
    assert(state.mutationEpoch(ticket) == publication + 1);
    assert(state.end(ticket));
    assert(!state.readable(publication));
}

static void test_overlap_never_becomes_exclusive_publication() {
    for (bool sameThread : {false, true}) {
        for (bool firstEndsFirst : {false, true}) {
            M::State state;
            M::Ticket first, second;
            assert(state.beginMutation(91, false, first));
            const uint64_t original = state.mutationEpoch(first);
            assert(original != 0);
            // The nestedClear hint has no exemption outside a selected SET22
            // operation, even when this second writer uses the same thread.
            assert(state.beginMutation(sameThread ? 91 : 92, true, second));
            assert(!state.mutationEpoch(first));
            assert(!state.mutationEpoch(second));
            M::Ticket &ended = firstEndsFirst ? first : second;
            M::Ticket &remaining = firstEndsFirst ? second : first;
            assert(state.end(ended));
            // Neither a formerly overlapped entry nor an invalidated outer
            // writer may publish after the competing writer has returned.
            assert(!state.mutationEpoch(remaining));
            assert(state.end(remaining));
            assert(state.snapshotEpoch() == original + 1);
            assert(!state.readable(original));
        }
    }

    M::State selectedState;
    M::Ticket selected, nested;
    const uint64_t epoch = selectedState.snapshotEpoch();
    assert(selectedState.beginSelected(epoch, 93, selected));
    assert(!selectedState.mutationEpoch(selected));
    assert(selectedState.beginMutation(93, true, nested));
    assert(!selectedState.mutationEpoch(nested));
    assert(selectedState.end(selected));
    assert(!selectedState.mutationEpoch(nested));
    assert(selectedState.end(nested));
}

static void test_poison_revokes_exclusive_publication() {
    M::State state;
    M::Ticket writer, overflowing;
    M::TestAccess::setEpoch(state, std::numeric_limits<uint64_t>::max() - 1);
    assert(state.beginMutation(101, false, writer));
    assert(state.mutationEpoch(writer) == std::numeric_limits<uint64_t>::max());
    assert(!state.beginMutation(102, false, overflowing));
    assert(!state.mutationEpoch(writer));
    assert(state.end(writer));
    assert(!state.snapshotEpoch());
}

int main() {
    test_initial_snapshot_and_selected_ticket();
    test_only_nested_clear_on_selected_thread_preserves_epoch();
    test_foreign_writer_during_selected_operation();
    test_multiple_writers_and_new_snapshot();
    test_wrong_duplicate_and_reused_tickets();
    test_epoch_overflow_permanently_poisons();
    test_writer_count_overflow_permanently_poisons();
    test_exclusive_mutation_publication_epoch();
    test_overlap_never_becomes_exclusive_publication();
    test_poison_revokes_exclusive_publication();
}
'''


class DisassociateMemoryTests(unittest.TestCase):
    def test_locked_generation_and_writer_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            source, binary = Path(tmp) / "test.cpp", Path(tmp) / "test"
            source.write_text(HARNESS)
            subprocess.run(
                ["xcrun", "clang++", "-std=c++14", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(PROJECT / "src"), str(source), "-o", str(binary)],
                check=True, capture_output=True, timeout=30,
            )
            subprocess.run([str(binary)], check=True, capture_output=True, timeout=15)


if __name__ == "__main__":
    unittest.main()
