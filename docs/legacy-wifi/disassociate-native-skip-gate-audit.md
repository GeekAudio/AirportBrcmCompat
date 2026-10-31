# Native SET22 skip-path and WorkLoop gate audit

## Scope

Read-only review of the retained El Capitan 4331 and 43224 child binaries, the current `readNativeIdle` / `completeNativeIdle` / `perform` paths, and the outer BSD dispatch gate. This checks the native setter branch taken when command `0x34` is skipped, with special attention to helper calls that might sleep or release the WorkLoop gate. It is a static audit of these pinned samples, not a runtime or hardware result.

## Fixed samples

| Child | Retained binary | SHA-256 |
|---|---|---|
| 4331 | `build/research/oclp-legacy/elcap-analysis-inputs/AirPortBrcm4331.bin` | `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e` |
| 43224 | `build/research/oclp-legacy/elcap-analysis-inputs/AppleAirPortBrcm43224.bin` | `fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165` |

Both paths are the retained child inputs referenced by `tools/verify_legacy_disassociate_contracts.py`; that verifier is offline and does not load or call the drivers. The outer provider and child contract reports are retained separately.

## Gate established by the bridge

`src/legacy_wifi_compat/legacy_install.cpp:309-322` requires the controller and interface to share a WorkLoop and requires `loop->inGate()` before entering the runtime dispatcher. The native SET22 request remains within that synchronous call. The cache lease also rechecks the same controller/interface/timer WorkLoop and gate in `legacy_install.cpp:174-182`.

## 4331 command-skip branch

The fixed setter is `__ZN16AirPort_Brcm433115setDISASSOCIATEEP8OSObject` at `[0xda90,0xdb4a)`. It calls `getVirtIf` at `0xdaa7`, obtains the `wlcif`, and calls `_wlc_bsscfg_find_by_wlcif` at `0xdac5` (return PC `0xdaca`). If the native predicate skips ioctl `0x34`, control branches to `0xdaf3`. From there the setter only:

1. Calls `OSMetaClassBase::safeMetaCast` at `0xdafd`.
2. Resets local authentication fields at `0xdb17..0xdb24`.
3. Calls `_bzero` at `0xdb37` for six local bytes.
4. Returns zero at `0xdb48`.

There is no sleep, `commandSleep`, WLC command, or explicit WorkLoop gate call in this post-`CfgFind` skip path. The `_IOSleep` import is used elsewhere in the child image; it is not called in the setter interval above. `getVirtIf` runs before `CfgFind` and is outside this branch-specific conclusion.

## 43224 command-skip branch and mode predicate

The fixed setter is `__ZN17AirPort_Brcm4322415setDISASSOCIATEEP16IO80211Interface` at `[0x98bc,0x992a)`. When it skips `_wlc_set(...,0x34,...)`, it still calls `AirPort_Brcm43224::setIBSS(false)` at `0x98f0`, clears local controller fields at `+0x468`, `+0x467`, `+0x404`, zeroes six bytes at `+0x408`, and returns zero.

The helper `AirPort_Brcm43224::setIBSS(bool)` is `[0x4d3a,0x4e42)`. For `false`, it first clears controller `+0x590`, loads WLC from controller `+0x418`, and checks the one-byte field `wlc+0x263a`:

- `wlc+0x263a != 0`: the helper branches directly to its return at `0x4e31`. It does not call `_wlc_down`, `setAP`, `_wlc_set`, `_wlc_get`, or `_wl_up`; the only helper-side write is the local `controller+0x590` clear.
- `wlc+0x263a == 0`: it enters mode reconfiguration. If the object at controller `+0x420`, byte `+0x20` is nonzero, it calls `_wlc_down` (`0x4d90`); it then calls `setAP(false)` and `_wlc_set` with command `0x14` and value `1`. For a specific `controller+0x53c == 4` case it also sets `0x92`; it calls `_wlc_get(0xf5)`, may set `0xf4`, and calls `_wl_up` (`0x4e2c`) when the prior up byte was nonzero.

The `0x14` command is Broadcom `WLC_SET_INFRA` (`20` in the retained public `wlioctl.h` definitions). The `_wlc_ioctl` jump table entry for selector `0x14` resolves from table base `0x6ac28` to handler `0x67fe3`; that handler writes the requested boolean with `setne byte [wlc+0x263a]` at `0x67ffa`. This identifies `wlc+0x263a` as the infrastructure-mode byte for this sample. The native `setIBSS(false)` passes value `1`, so its zero-byte path is the IBSS-to-infrastructure transition. Any nonzero byte takes the already-infrastructure early return; the test is zero-versus-nonzero, not equality to exactly `1`.

Therefore the safe idle candidate for 43224 must require `wlc+0x263a != 0` before the setter and recheck it after the setter and after the outer provider returns. A zero value is not a no-op case, even if association/type/state fields are zero. If the zero-value path calls the installed `_wlc_down` route, its `Mutation` advances the child memory epoch, so `completeNativeIdle` rejects the original epoch and the idle-success branch cannot be claimed.

The current source now checks the one-byte nonzero infrastructure value in `readNativeIdle` at `disassociate_kernel.cpp:238-253`. The same helper is called before the 43224 setter (`:364-367`), after it (`:259-266`), and again after the outer handler (`:1058-1065`), so the predicate is repeated at all three points. The observation stores only the WLC/cfg/association pointers; this is sufficient for the mode predicate because the native test itself is zero-versus-nonzero, and `readNativeIdle` rechecks that predicate on every pass. I reviewed this source shape only; this audit did not run tests or a build.

For the guarded nonzero path, `setIBSS(false)` contains no sleep or WorkLoop release call; the lower down/up/timer/WLC helpers are not reached. The unguarded zero path does invoke `_wlc_down`, `_wl_del_timer` virtual callbacks, WLC ioctl handlers, and possibly `_wl_up`; this audit does not claim those deeper paths preserve the gate because they must be excluded from the accepted idle case.

## Conclusion and boundaries

- 4331's post-lookup skip cleanup is local and does not sleep or issue another command in the pinned function body.
- 43224's skip branch is only an idle no-op candidate if its current infrastructure-mode byte is already nonzero. Without that predicate it can perform a full mode reconfiguration and may cycle WLC down/up.
- With the nonzero infrastructure predicate, the accepted 43224 helper branch is straight-line local cleanup, and the outer bridge's same-WorkLoop `inGate()` check remains the relevant gate proof.
- This does not prove every unrelated native virtual call or the entire child image is gate-preserving. It specifically excludes the reconfiguration path containing the unresolved timer virtual callback at `Timer::delTimer`'s `timerSource` vtable slot `+0x218` and WLC ioctl dispatch.
- The idle return in `perform` does not invoke `CacheKernel::prune`, including when a flush field is present. This report reviews the local skip predicate and gate safety only; it does not claim that this path consumed flush metadata or is equivalent to every upstream FSM state. The retained `disassociate-empty-state-semantics.md` describes the state-specific native flush boundary.
- No production code, README, or runtime configuration was changed for this audit.

## References

- Retained binaries and SHA-256 values: table above.
- Child body/route verifier: `tools/verify_legacy_disassociate_contracts.py`.
- Gate guard: `src/legacy_wifi_compat/legacy_install.cpp:309-322`.
- Idle implementation reviewed: `src/legacy_wifi_compat/disassociate_kernel.cpp:213-265`, `355-409`, `999-1072`.
- Broadcom ioctl definitions corroborating `WLC_SET_INFRA = 20`: [retained public wlioctl.h mirror](https://github.com/spotify/linux/blob/master/drivers/staging/brcm80211/include/wlioctl.h).
