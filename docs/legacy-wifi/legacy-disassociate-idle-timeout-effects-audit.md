# Legacy state-zero timeout side effects

Read-only continuation of `legacy-disassociate-idle-predicate-audit.md`. Scope is limited to the state-zero timeout route in the retained 4331 and 43224 children, including the next event-construction layer. The question is whether state 0 with type `AS_IDLE` can itself retry or restart association. This is static binary evidence, not live state or host event-consumer evidence.

## Samples

| Sample | SHA-256 |
|---|---|
| `AirPortBrcm4331.bin` | `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e` |
| `AppleAirPortBrcm43224.bin` | `fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165` |

## 4331

`_wlc_assoc_timeout` at `0xade7e` reads `assoc+0x0c` at `0xadf19`. For state 0, the jump table target `0xadf37` prepares `status=2` (`esi`) and tail-jumps to `_wlc_auth_complete` at `0xadf64`.

`_wlc_auth_complete` begins at `0xae0a8`. It reads the same assoc state at `0xae14e`. State 7 and state 9 take the specialized branch at `0xae160`; all other states, including 0, go to the generic event branch at `0xae40d`. That branch sets event code `3`, puts the timeout result (`2`) in the event argument carried in `r8d`, calls `_wlc_bss_mac_event` at `0xae43a`, then returns via `0xae4d8`. It does not change assoc type/state and does not reach the `_wlc_join_bss_start` call at `0xae34a`, which is on the separate state-7/9 path.

The 4331 `_wlc_bss_mac_event` wrapper at `0x259e9` forwards to `_wlc_bss_mac_rxframe_event` at `0x4eebb`. The latter calls `_wl_event_sync` at `0x4efd4`, then enqueues the event at `0x4eff1`. For this event-code-3 input, the retained `_wl_event_sync` entry compares the event code with `0x20`; the `jne` at `0x16c1a` takes the mismatch return at `0x16c3c`, after which the caller continues to queue insertion. The guard pins the two code spans `[0x16c10,0x16c1c)` and `[0x16c3c,0x16c43)`, the `jne` opcode and target, and the caller's direct call target bound to the `_wl_event_sync` symbol. It does not pin the `0x20` branch or the relocated `willRoam` call.

The callback code does not read `assoc+0x08` (`type`). Therefore, when the requested joint condition also has `type == AS_IDLE` (zero), the observed state-zero behavior is still this event-and-return route, with no restart in the child path.

## 43224

`_wlc_assoc_timeout` at `0x5eb02` reads `wlc+0x379c` at `0x5eb5f`. State 0 branches to `0x5eb7f`, which calls `_wlc_bss_mac_event` at `0x5ebf3` with event code `3` (`edx`) and field `+8 = 2` (`r8d`). The branch does not read `wlc+0x3798` (`assoc_type`), write the association state, or call a join function.

The callee `_wlc_bss_mac_event` at `0x7f4ca` allocates an event object, stores event code and fields (`0x7f51b..0x7f559`), associates the interface with it (`_wlc_event_if` at `0x7f595..0x7f59e`), then enqueues it (`0x7f5bb`). `_wlc_eventq_enq` links the event into the queue and, if the queue was idle, schedules queue processing through `_wl_add_timer` (`0xa55e8..0xa55fd`). This layer packages and queues an event; it does not invoke association/join from this callback route.

As with 4331, the callback does not inspect type. With state 0 and type `AS_IDLE` (zero), the observed result remains event construction and queueing, not an internal retry or re-association.

## Conclusion and bounds

For the pinned child binaries, the candidate primary-STA predicate from the parent audit—non-AP, not associated, type `AS_IDLE`, state 0, and verified primary ownership—rules out an automatic retry/re-association in these two state-zero timeout callback paths. The callbacks can still emit an event with code 3 and detail field 2. A queued or late event alone is not evidence that association remains in flight and does not invalidate a driver-level idempotent no-op.

This does **not** establish what a higher-level event consumer may do after receiving the event, nor prove that no callback is queued. The 4331 check establishes only that event code 3 takes the guarded mismatch-return branch instead of the `0x20` `willRoam` branch before queue insertion. The 43224 check establishes event construction and queue handoff only. These are child-binary prerequisites; they do not independently validate the runtime idle no-op implementation, establish that no event is queued, or prove global callback/reconnect quiescence.

## Minimal admission guards for this bounded claim

The existing `DisassociateChildContract` already pins both complete SET22 handlers, so its handler gate must remain the source of the native skip condition. For the new predicate and timeout claim, add complete function-body guards (with the existing verifier's exact symbol/range/raw-or-normalized hash and relocation/import checks) for:

| Child | Function | Body span | Why it is needed |
|---|---|---:|---|
| 4331 | `_wlc_assoc_change_state` | `[0xad25f, 0xad420)` | Confirms the association state dword is read/written at context `+0x0c`. |
| 4331 | `_wlc_bsscfg_down` | `[0x5de67, 0x5e0aa)` | Confirms context `+0x0c` and type `+0x08` checks, including the `AS_IDLE` assertion path. |
| 4331 | `_wlc_assoc_timeout` | `[0xade7e, 0xae0a8)` | Pins the state-zero dispatch and the status-2 handoff to auth completion. |
| 4331 | `_wlc_auth_complete` | `[0xae0a8, 0xae54c)` | Pins the state-zero-to-event branch and ensures it does not take the state-7/9 join path. |
| 4331 | `_wlc_bss_mac_event` | `[0x259e9, 0x25a1d)` | Pins the event wrapper target. |
| 4331 | `_wlc_bss_mac_rxframe_event` | `[0x4eebb, 0x4eff6)` | Pins event construction, interface association, and queue handoff. |
| 4331 | `_wlc_eventq_enq` | `[0x811d3, 0x81247)` | Pins that the downstream in-child step links/schedules the event queue rather than invoking an association path. |
| 43224 | `_wlc_assoc_change_state` | `[0x57347, 0x573bb)` | Confirms the WLC state dword is read/written at `+0x379c`. |
| 43224 | `_wlc_bsscfg_down` | `[0x8ffa6, 0x900d5)` | Confirms the `+0x379c` state and `+0x3798` type checks, including `AS_IDLE`. |
| 43224 | `_wlc_assoc_timeout` | `[0x5eb02, 0x5ec84)` | Pins the state-zero event-code-3/detail-2 branch. |
| 43224 | `_wlc_bss_mac_event` | `[0x7f4ca, 0x7f5ec)` | Pins event construction and the queue handoff. |
| 43224 | `_wlc_eventq_enq` | `[0xa558e, 0xa5602)` | Pins the in-child queue insertion/scheduling step. |

For the 4331 synchronous handoff, runtime Admission independently resolves `_wl_event_sync` as a named child-image symbol at `0x16c10`, and the verifier checks its Mach-O nlist visibility. The caller's internal branch is also pinned to that address. The selected ranges pin the comparison/branch and mismatch-return epilogue. The guard intentionally excludes `_wl_event_sync`'s event-`0x20` `willRoam` branch and any later event consumer. The range hashes and the rel8 branch target are mutation-tested; the external `willRoam` relocation is outside the selected ranges and is not treated as a resolved dependency.

## 43224 idle setter path

The 43224 `setDISASSOCIATE` handler has a direct call at `0x98f0` to `AirPort_Brcm43224::setIBSS(bool)` at `0x4d3a`. The full `setIBSS` body `[0x4d3a,0x4e42)` is now pinned and all seven direct in-image calls have independently verified targets. In the `false` input case, when `wlc+0x263a` is nonzero, its branch returns status 0 after clearing the controller's `+0x590` byte and bypasses the reconfiguration path (`_wlc_down`, `setAP`, `_wlc_set`, `_wlc_get`, `_wl_up`). This guard supplies a static precondition for the matching runtime observation; it does not itself prove that runtime observation or broaden the state-zero timeout claim.

The existing SET22 bodies are already full guards: 4331 `__ZN16AirPort_Brcm433115setDISASSOCIATEEP8OSObject` `[0xda90, 0xdb4a)`; 43224 `__ZN17AirPort_Brcm4322415setDISASSOCIATEEP16IO80211Interface` `[0x98bc, 0x992a)`. The runtime no-op admission must additionally require the actual skip predicate: 4331 `cfg+0x0a==0 && cfg+0x0b==0`; 43224 `wlc+0x3b==0 && wlc+0x2f==0`. Apply the child-specific primary-owner and idle type/state checks from the prior audit.

For the queue helpers, checking only a resolved call target is insufficient to support the stronger statement “this child path only queues an event”: the implementation at that target could change while the call remains pointed there. Pinning the complete `_wlc_eventq_enq` body is the narrow guard for the observed queue-only operation. The limit remains the queue handoff; do not claim that host event consumers cannot initiate a separate reconnect. Each full function guard must also enumerate its direct external relocation calls/imports for the existing verifier, rather than hashing loader-relocated operands as stable bytes.

No production source, tests, EFI, or loaded driver were changed.
