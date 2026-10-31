# Gated legacy SET22 idle candidate

This is a candidate source change, not loaded-driver or all-system/card validation. The requested full compatibility goal remains incomplete and no commit or deployment is authorized by this checkpoint.

## Request semantics

The retained Tahoe LINK_DOWN/event4 action returns success without reading reason/flush payload or pruning cache. This is true even when a stale current-BSS object remains retained. The old setter may likewise skip command0x34 while clearing its local interface/authentication state. A zero setter result or a missing worker alone does not identify that branch.

The new branch in `src/legacy_wifi_compat/disassociate_kernel.cpp` accepts only an observed primary STA idle predicate, with the actual native setter skip condition, in the already verified synchronous controller WorkLoop gate. `CacheKernel::Lease::current()` independently checks the primary binding, manager generation, common WorkLoop and `inGate()`; `safeThread()` alone is insufficient. The main mutation epoch protects routed BSS/config/WLC teardown windows. Association state and in-place initialization remain serialized by the WorkLoop gate, not by pretending every field is covered by the body mutation epoch.

## Observations

- 4331: capture only after the exact setter CfgFind call returns and before returning to the setter's associated/AP branch. Bind its aligned cfg back to the controller WLC, require AP/associated/alternate bytes zero, and require its non-null0x60-byte association context at cfg+0x320 to have type+8 and state+0xc both zero. The context's known allocation/free path is the existing cfg malloc/mfree lifecycle; STA reinitialization zeroes the same allocation under the gate.
- 43224: capture at setter entry. Require controller+0x418 and+0x420 to name the same WLC, primary cfg at WLC+0xf10, WLC AP+0x2f/associated+0x3b/alternate+0x3a and primary cfg AP byte zero, sta_associated byte+0x10e8 zero, infrastructure byte+0x263a nonzero, and dwords assoc_type+0x3798/state+0x379c zero. In particular, the setter's own+0x3b skip predicate cannot be replaced by the STA flag alone. The setter calls `setIBSS(false)` even when command0x34 is skipped: only the already-non-IBSS branch (byte+0x263a nonzero) returns after clearing controller+0x590 without down/up or mode configuration. Both the full helper body and this predicate are required; a mode-changing request cannot use the idle exception.
- Call the original setter once. It must return0 and neither disable nor worker may have been observed. Re-read the complete idle tuple with the same live lease, main epoch and WLC/cfg/context pointers.
- After the outer original handler returns, preserve any original error first. Only a completed idle observation can take the exception to normal worker completion; recheck live lease, epoch, the complete idle tuple and all three pointers once more, then consume the private stack observation.
- Idle processing never follows a current BSS/body pointer, constructs a reason frame, or prunes cache. Stale BSSID/body bytes do not identify idle and do not invalidate an independently proven idle request. No synthetic disable/abort helper is invoked. Normal associated disconnect retains its existing one-shot worker completion and cache-prune rules.

## Binary admission and boundaries

The added contracts pin association state/layout readers and the retained state-zero timeout/event path. For4331, the synchronous event helper's event3 mismatch path is checked independently of its unexecuted event0x20/willRoam branch. The evidence stops at event queue handoff: it does not prohibit a subsequent independent host reconnect request. The existing fixed child identity and provider admission remain required.

Known paths include controller-gated BSD ioctl, timer, receive and event-queue callbacks. The static audit is not a complete indirect-call graph; runtime route ordering, gate behavior and actual card/system operation still require validation. No separate association epoch is introduced: routing only the central state changer would miss earlier type stores, while reusing the body epoch would incorrectly invalidate normal disconnect completion.

## Evidence

- `disassociate-empty-state-semantics.md/.json`
- `legacy-disassociate-unassociated-state-audit.md/.json`
- `legacy-disassociate-idle-predicate-audit.md/.json`
- `legacy-disassociate-idle-timeout-effects-audit.md/.json`
- `legacy-4331-assoc-context-lifetime-audit.md/.json`

Test and artifact evidence is recorded separately after this source batch is frozen.
