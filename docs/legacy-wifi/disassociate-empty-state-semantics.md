# SET22 empty-current-network semantics (read-only)

## Scope and inputs

This audit compares the retained Tahoe host BootKC (`/System/Library/KernelCollections/BootKernelExtensions.kc`, SHA-256 `96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c`, `com.apple.iokit.IO80211Family` and `com.apple.driver.AppleBCMWLANCoreMac`) with the pinned El Cap OCLP provider/child samples. It reads retained disassembly only; no kernel path or wireless operation was executed and no production code was changed.

| Sample | SHA-256 |
|---|---|
| El Cap `IO80211ElCap.bin` | `8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0` |
| El Cap `AirPortBrcm4331.bin` | `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e` |
| El Cap `AppleAirPortBrcm43224.bin` | `fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165` |

## Tahoe WCL when its current-BSS slot is null

`WCLNetManager::setDISASSOCIATE` (`0xffffff8002195aa6`) reads reason and flush from request offsets `+4` and `+8`, then calls `leaveNetworkCommand` (`0xffffff8002192644`). That function initializes the outgoing reason to zero. If its current `WCLBSSBeacon` slot is null, it skips the `isNwAssuranceEnabledInCCXIE` call and leaves reason zero; it still writes the independent flush flag into event payload `+0x1c` and calls `CommonFsmManager::processEvent(LEAVE_NETWORK, ...)`.

The observed FSM routes event 4 by its current state:

| FSM state | Event-4 action | Empty-current-BSS implication |
|---|---|---|
| `LINK_DOWN` (state 0) | `joinAbort` | Action sends its cleanup bulletin messages as applicable, clears its local flag, and explicitly returns `0`; it does not purge scan cache. |
| `DEAUTH` (4), `SLEEP_DEAUTH` (6) | `ignore` | `ignore` is `xor eax,eax; ret`, a successful no-op. |
| `WAITING_FOR_CONNECT_COMPLETE` (1), `WAITING_FOR_IP` (2), `LINK_UP` (3), `SLEEP` (5) | `leaveNetwork` | This is not a no-op: it sends the link-down IOUC and normally follows with event 3. `linkDownComplete` guards selective pruning on both flush bit 0 and a nonnull saved BSS, so a null BSS skips `removeBeaconsMatching`; this path does not call the full scan-cache purge. Other link-down work can still occur. |

The normal active-state path therefore can continue without a BSS, but the static evidence does not equate every null BSS with FSM state 0. In particular, a null pointer by itself does not prove the whole operation is an immediate no-op or that every downstream IOUC action succeeds. The only established cache effect is that the selective removal call is not made without a saved BSS; no global flush is shown.

The native Family BSD/new-API wrappers do not inspect the BSSID or current-BSS pointer before routing SET22. They send the request to WCL and fall back to `apple80211setDISASSOCIATE` only when WCL is absent/unhandled or returns the designated unsupported status. That fallback calls the interface's type-22 virtual handler; the wrapper itself has no empty-BSSID branch. Thus any empty-network idempotence observed here belongs to the WCL/child route, not a generic Family BSSID check.

`AppleBCMWLANNetAdapter::leaveNetworkSync` has an early busy/in-progress branch (`core+0x40` bit 0) that returns zero before the normal path. That is evidence of success on a repeated/in-progress leave, not evidence that an all-zero BSSID is accepted or that no current BSS is the branch predicate. The normal method's exact empty-network outcome is not assigned here.

## Pinned legacy child behavior

The two retained child `setDISASSOCIATE` handlers accept no reason/flush payload. They each conditionally issue ordinary WLC command `0x34`, ignore that command's status, clear local association/authentication state, and return `0`:

* 4331 (`0xda90..0xdb49`): after resolving its config, it runs `0x34` only if `cfg+0x0b != 0` and `cfg+0x0a == 0`; otherwise it skips the command. It then resets its auth fields and returns zero.
* 43224 (`0x98bc..0x992a`): it runs `0x34` only if `cfg+0x3b != 0` and `cfg+0x2f == 0`; otherwise it skips the command. It then clears local/interface state and returns zero.

These are success-after-skip examples, but the audited bytes do not establish that those private config-byte predicates mean “BSSID absent” or “never associated.” Neither child path calls a scan-cache purge. The old worker therefore supports local idempotent cleanup under its own predicates, but does not implement modern reason/flush semantics.

## Compatibility conclusion

1. A request with no native WCL current BSS does not preserve a nonzero requested reason: the native WCL command leaves the reason at zero and continues dispatch. This is a deliberate default in the observed producer path, not a conversion to an IEEE reason code.
2. The flush flag is independent. With no saved BSS, the native `removeBeaconsMatching(savedBSS)` call is skipped; the audited SET22 path does not turn this into a global cache purge.
3. Native state-0 and state-4/6 event-4 actions return zero. Active states may still run link-down actions even with a null current BSS, so “null BSS means no-op” is too broad.
4. An all-zero six-byte BSSID is not proven equivalent to a null WCL current-BSS pointer, an FSM `LINK_DOWN` state, or either old child's private skip predicate. The current DK check that refuses to manufacture a current-network identity from all-zero BSSID is conservative. The samples do not prove that it should return success for every such request.
5. No sample shows global cache clearing for this empty SET22 case. The Tahoe full cache purge is a separate SET90 route; SET22's evidenced flush operation is identity-targeted and requires a saved BSS.

## Evidence pointers

* Tahoe WCL field/FSM/cache trace: `tahoe-native-wcl-disassociate-audit.md/.json`; `tahoe-native-wcl-net-setDISASSOCIATE.asm`, `tahoe-native-wcl-net-leaveNetworkCommand.asm`, `tahoe-native-wcl-net-linkDownComplete.asm`, `tahoe-native-wcl-common-processEvent.asm`, `tmp-native-wcl-joinAbort.asm`, `tmp-native-wcl-ignore.asm`.
* Tahoe Family dispatch/fallback boundary: `tahoe-native-family-disassociate-audit.md/.json`, `tahoe-native-bsd-set22-handler.asm`, `tahoe-native-iouc-set22-handler.asm`, `tahoe-native-__Z25apple80211setDISASSOCIATE.asm`.
* Tahoe normal/in-progress adapter path: `tmp-audit-ZN22AppleBCMWLANNetAdapter16leaveNetworkSyncEj11LeaveMethodjt10etheraddrPKc.asm`.
* Old handlers/current-network limitations: `legacy-disassociate-current-network-audit.md/.json` and the two child `setDISASSOCIATE` disassemblies listed above.

Static binary evidence only. No runtime, RF, or hardware behavior is claimed.

## Follow-up: action ownership and completion timing

### `LINK_DOWN` / `joinAbort` does not clear a BSS reference

`joinAbort` (`0xffffff8002194828`) sends an unconditional bulletin message `0x90003`, conditionally sends `0x60003` and `0xd0003`, clears a byte at manager-private offset `+0x439`, and returns zero. Its body does not call `WCLNetManager::setCurrentBSS`, retain/release a `WCLBSSBeacon`, or access the BSS manager's current slot. Therefore `joinAbort` itself does not cancel/clear a saved BSS reference in the audited body.

The unconditional `0x90003` message is translated by `WCLGlue::sendMessageToDriver` to an internal SET request for selector 9. In the retained Tahoe `apple80211RouteInternal` table, `gInternalSetHandlerTable[9-1]` is null; the router's null-handler path keeps the default unsupported result `0x66`. `joinAbort` does not test the bulletin-send return and still returns zero. The conditional selector-6 and selector-13 messages likewise point to null slots in this table. On this sample, these messages are not proof of an in-flight association cancellation. No direct join-cancel operation or BSS-reference release is shown in `joinAbort`.

This gives a narrow native success case: when the FSM really is in `LINK_DOWN` state 0, event 4 selects `joinAbort` and returns zero even though the optional internal SET messages are unsupported. This state is stronger evidence than an all-zero BSSID; the Family entry does not read or test the BSSID to select it.

For the stipulated stationary-STA case—current BSS absent, no association or leave in flight, and the WCL state confirmed as `LINK_DOWN`—the native request has no `0x1a9` reason-side action and no flush/cache action; it returns zero after its WCL-local housekeeping. A legacy request handler that performs its own local cleanup and returns zero is therefore equivalent at the request result and network/cache-effect boundary for this narrow case. This does not show that the old child reproduces the private WCL byte at `manager+0x439`, nor does it make zero BSSID alone a valid idle-state test. Without a trustworthy idle/no-inflight predicate, this success case cannot safely be inferred.

### `DEAUTH` / `ignore` can coexist with a live current-BSS reference

The FSM transitions into `DEAUTH` state 4 before it invokes `leaveNetwork`. `leaveNetwork` first sends selector `0x1a9`, then normally dispatches event 3; only `linkDownComplete` later reads the current-BSS slot and calls `setCurrentBSS(nullptr, ...)`. A special `0x1a9` result (`0xe0821806`) plus manager/controller predicates skips event 3, so state 4 can persist without that slot being cleared. Consequently, a later event 4 in state 4 can select `ignore` while a current BSS is still present. `ignore` returns zero and does not read the event payload, clear the BSS, or prune cache.

State 6 is reached from `SLEEP` state 5 through the same `leaveNetwork` action; the audit does not prove a separate release in the `ignore` action. Any later event-3 cleanup is from another event path and uses that event's payload/current BSS. The second request's flush bit is not retained by `ignore`.

### The flush flag is not queued by the no-op branches

For state 0, `joinAbort` never reads payload byte `+0x1c` and does not call `removeBeaconsMatching` or `purgeScanCache`. For states 4/6, `ignore` is only a zero-return stub, so it also does not read or queue the flush flag. A later cleanup could still be caused by an already-running earlier leave operation, but its pruning decision uses the earlier operation's retained payload; this audit finds no path that attaches the ignored request's flag to that completion.

There is also a distinct `WCLNetManager::linkDownInd` message handler (`0xffffff8002193120`). It retains the then-current BSS and, on an event-derived `r13b` branch, calls `removeBeaconsMatching(currentBSS)` at `0x2193884`. Its input dispatch uses the incoming message's `+8` event selector; the handler does not read that message's `+0x1c` flush byte. This proves a later link-down indication can independently prune when its own conditions hold, but it does not prove that a no-op SET22 queued such an indication or that the request's flush bit caused the removal. The caller/timing and relation to any particular SET22 remain unproven.

On the normal active-state route, this is an inline two-stage call path, not a separate flush completion callback: `leaveNetwork` synchronously calls `cmdIouc(0x1a9, ...)`, then directly calls `processEvent(3, ...)` at `0x21946a5`; the event-3 action `linkDownComplete` performs the conditional `removeBeaconsMatching` before returning. The exact special `0xe0821806` branch can skip the event-3 call, so it can return the selector-`0x1a9` status without applying the flush prune. The WCL return is not an over-the-air/AP completion acknowledgement.

Reason and flush therefore have distinct effects but no distinct asynchronous result in this call chain. Reason is gated before event 4 and can be zeroed before the `0x1a9` call; the `0x1a9` call performs the reason-dependent native vendor-IE work. Flush is carried separately in the event payload and only acts during event 3 when a saved BSS exists. In states 0/4/6 neither metadata field is forwarded through the normal `leaveNetwork` action: state 0 returns through `joinAbort`, and states 4/6 through `ignore`. In active states a flush-only request can still run `0x1a9` with reason zero, then prune on normal event 3; if event 3 is skipped, the reason action may have run while the flush action did not.

### Exact remaining boundary

The static path establishes a zero-return/no-request-flag-prune branch for FSM state 0 and duplicate event-4 no-op branches in states 4/6. A separate later `linkDownInd` can prune its then-current BSS under its own event-derived condition, but cannot be attributed to this request's flush flag from the inspected path. The audit does not establish that old child link state or zero BSSID reliably identifies state 0, that a no-op branch has no prior leave in flight, or that an already-in-progress leave will complete later. Such a prior operation may still hold a current BSS until its own `linkDownComplete`; the flush byte on that earlier payload controls that completion's removal. Do not treat “no worker ran” alone as proof that the request's metadata was consumed.
