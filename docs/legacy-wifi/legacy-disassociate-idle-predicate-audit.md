# Legacy SET22 idle / abort predicate audit

Read-only audit of the retained El Capitan 4331 and 43224 child binaries. The question is whether local state fields can prove that a primary STA is idle enough to turn a skipped SET22 into a successful no-op, and whether `_wlc_bsscfg_disable` can safely serve as a synchronous abort. This is static evidence only; it does not prove live device state.

## Samples

| Sample | SHA-256 |
|---|---|
| `AirPortBrcm4331.bin` | `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e` |
| `AppleAirPortBrcm43224.bin` | `fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165` |

## Candidate local idle fields

| Child | Candidate fields for an already-idle primary STA | Evidence |
|---|---|---|
| 4331 | `cfg+0x0a == 0` (not AP); `cfg+0x0b == 0` (`associated` false); non-null assoc context at `cfg+0x320`; `assoc+0x08 == 0` (`AS_IDLE` type); `assoc+0x0c == 0` (state) | SET22 tests the two cfg bytes at `0xda90`. `_wlc_bsscfg_down` reads assoc state at `0x5deaf` and asserts the type string `bc->assoc->type == AS_IDLE` at `0x5dfa4` when type is nonzero. `_wlc_assoc_change_state` uses the context state dword at `+0x0c` (`0xad25f..0xad2a9`). |
| 43224 | `wlc+0x2f == 0` (not AP); `wlc+0x10e8 == 0` (`sta_associated` false); `wlc+0x3798 == 0` (`AS_IDLE` type); `wlc+0x379c == 0` (state) | `_wlc_bsscfg_down` checks state at `0x90042`, then asserts `wlc->assoc_type == AS_IDLE` at `0x9005d`. `_wlc_assoc_change_state` reads/writes the state dword at `+0x379c` (`0x57347..0x573af`). The device SET22 gate is a different pair: `wlc+0x3b != 0 && wlc+0x2f == 0` at `0x98bc`. |

These are candidate snapshots, but the retained fields do not tell us whether an association timer callback is queued:

* 4331 initializes an `assoc` timer with callback `_wlc_assoc_timeout` at `0x5f0c1..0x5f0db`. That callback reads the assoc state at `0xadef19`; state `0` has a dedicated branch at `0xadf37` that reaches `_wlc_auth_complete` at `0xadf64`. `_wlc_assoc_abort` at `0xaeaea` returns immediately when the same state dword is zero (`0xaeb05..0xaeb0a`), before its scan-abort, timer-deletion, and state-specific cleanup paths.
* 43224 initializes its `assoc` timer with callback `_wlc_assoc_timeout` at `0x5d9e2..0x5d9f8`. The callback reads state at `0x5eb5f`; state `0` takes a dedicated branch `0x5eb7f..0x5ebf3` and calls `_wlc_bss_mac_event`. `_wlc_assoc_abort` at `0x5ca04` likewise has a zero-state early return before its nonzero-state cancellation logic.

This is not proof that a zero-state callback is pending, that association remains in flight, or that the callback re-starts association. A delayed failure notification could be harmless to the requested no-op semantics. The remaining unknown is the actual side effect of each child’s state-0 timeout branch, including whether it can retry or re-associate when the type is also `AS_IDLE`. The local fields alone neither resolve that question nor establish callback quiescence.

## `_wlc_bsscfg_disable` is not a narrow abort substitute

Both implementations perform broader configuration shutdown and cleanup rather than a join-only abort:

* 4331 `_wlc_bsscfg_disable` (`0x5e0aa`) calls `_wlc_bsscfg_down` (`0x5e199`), conditionally calls `_wlc_disassociate_client` or `_wlc_sta_assoc_upd(false)` (`0x5e1c6..0x5e217`), attempts association timer deletion (`0x5e217..0x5e240`), clears the cfg-up bit (`0x5e24b`), and can clear SCB state (`0x5e26f..0x5e278`). Its return at `0x5e27d` is an accumulated cleanup result; it is not a callback-drain or association-quiescence token.
* 43224 `_wlc_bsscfg_disable` (`0x900d5`) calls `_wlc_bsscfg_down` (`0x90196`), conditionally invokes `_wlc_disassociate_client` or `_wlc_sta_assoc_upd(false)` (`0x901c0..0x901fa`), attempts association timer deletion (`0x901fe..0x9020c`), clears cfg state (`0x90211..0x90219`), and may clear SCB state (`0x90240..0x90249`). The function does not return a documented association-completion indication; its tail computes cleanup-related counts and optionally clears SCB state.

Calling disable from the SET22 compatibility path would change the enabled state and cleanup scope of the primary BSS configuration. The code does not show it waiting for all already queued callbacks to drain, and its return value cannot certify that they have. It is therefore not a safe substitute for an idempotent SET22 no-op or for a precise association abort.

## Decision

The narrowest defensible candidate for a *local idle snapshot* is the child-specific conjunction in the table plus a verified primary STA owner. The focused follow-up found that the examined state-0 timeout paths emit/queue event code 3 with detail value 2 and do not themselves retry or re-associate; see `legacy-disassociate-idle-timeout-effects-audit.md`. This supports a driver-level idempotent no-op for the bounded child path. It does not prove no event is pending or that a higher-level event consumer cannot initiate a separate reconnect. Do not infer completion from all-zero BSSID or `GET_STATE == 0` alone. Do not call `_wlc_bsscfg_disable` to manufacture an abort.

No source, tests, EFI, or loaded driver were changed.
