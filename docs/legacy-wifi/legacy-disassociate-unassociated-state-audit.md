# Legacy SET22 behavior when apparently unassociated

Read-only static audit of the retained El Capitan provider and pinned 4331 / 43224 child binaries. This addresses whether a zero or unavailable legacy BSSID is enough to treat SET22 as a successful no-op. It is not runtime or RF evidence.

## Inputs

| Sample | SHA-256 |
|---|---|
| `IO80211ElCap.bin` | `8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0` |
| `AirPortBrcm4331.bin` | `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e` |
| `AppleAirPortBrcm43224.bin` | `fcbc111f3aa0d27bc61f17b558f5bcbaa6a8aa3d1d9370bed6eea9be4c9ce165` |

Function bytes and focused disassemblies for the GET_BSSID and SET_DISASSOCIATE entry points are in `legacy-disassociate-current-network-function-evidence.json`. The provider SET22 and child worker contract is further described in `legacy-current-bss-internal-audit.md` and `disassociate-empty-state-semantics.md`.

## GET_STATE and GET_BSSID are not equivalent to a no-association predicate

Both child `getSTATE` functions write version 1. They write state value 4 only when `IO80211Interface::linkState()` returns exactly 2; otherwise they return success and leave the state field at zero (`4331 0x98c4..0x9937`, `43224 0x6938..0x698a`). These functions do not read the WLC current-BSS BSSID, association context, or an in-flight join token. Therefore `GET_STATE.state == 0` establishes only that this sampled getter did not observe linkState 2.

The BSSID getters are also gated:

* **4331** `getBSSID` (`0x9478`) resolves a `bsscfg`, requires `bsscfg+0x0b & 1`, and on the ordinary-interface path also requires linkState 2 before issuing WLC command `0x17` for six bytes. A false gate returns the initial length value without populating the BSSID output in this method.
* **43224** `getBSSID` (`0x66a2`) requires the WLC byte `wlc+0x3b != 0`, and on the ordinary user path also requires linkState 2, before issuing command `0x17`. A false gate likewise skips the BSSID query; it is not a verified all-zero BSSID result.

Thus a BSSID output buffer that happens to contain six zero bytes cannot be attributed to either child's getter without also checking whether that getter actually populated the bytes. Neither GET_STATE nor GET_BSSID tests “no association in progress.”

## 4331 SET_DISASSOCIATE

At `0xda90`, the setter resolves the optional interface to a `wlcif`, finds the `bsscfg`, and enters WLC command `0x34` only if:

```
bsscfg + 0x0b != 0
and
bsscfg + 0x0a == 0
```

The `+0x0b` identity is supported by source-assertion literals in the same binary: code at `0x25bc8` tests that byte and asserts the string `cfg->associated`; `wlc_BSSinit` at `0x26db6` tests the same byte and asserts `!cfg->associated`. The `+0x0a` byte is the AP/BSS configuration branch: `_wlc_bsscfg_up` (`0x5dbb6`) calls `_wlc_ap_up` when it is set, and `_wlc_bsscfg_disable` (`0x5e0aa`) takes its AP-specific cleanup path when set.

The setter does not read the current-BSS record at `bsscfg+0x318` or its BSSID. If the command predicate is false, the handler still resets local authentication fields, clears its six-byte local interface field, and returns zero. If the command is entered, its result is ignored and the handler still returns zero.

There is an independent association context at `bsscfg+0x320`. `_wlc_bsscfg_down` (`0x5de67`) checks that context and calls `_wlc_assoc_abort` when its state dword at context `+0x0c` is nonzero (`0x5dea6..0x5dec1`). The SET_DISASSOCIATE predicate does not inspect this context. This proves the child has a separate state path for aborting an in-progress association; it does not, by itself, prove a particular live tuple of `associated==0` plus pending context for every call. The exact ordinary no-current joint state remains unobserved.

## 43224 SET_DISASSOCIATE

The driver's `wlcStart` stores the same `_wlc_attach` result into driver fields `+0x418` and `+0x420` (`0x2f95..0x2fad`), so the setter's tested object at `this+0x420` is the WLC pointer used at `this+0x418`. At `0x98bc`, command `0x34` is issued only if:

```
wlc + 0x3b != 0
and
wlc + 0x2f == 0
```

Neither condition reads the current-BSS record at `wlc+0x2f8` or its BSSID. The `+0x3b` byte is changed by several lifecycle paths: `_wlc_assoc_scan_complete` sets it to 1 at `0x57e90`; `_wlc_join_adopt_bss` sets it to 1 at `0x828ca`; `_wlc_disassociate_client` writes `wlc+0x10ec != 0` to it at `0x6763f` and `0x67850`; `_wlc_bsscfg_disable` does the same at `0x901fa`. These writes show it is not a direct test of whether the current BSSID record is zero. The `+0x2f` test is an AP-lifecycle guard: `_wlc_ap_doiovar` sets WLC `+0x2f` on AP disable/update paths (`0xa78a8`, `0xa7cfd`). The retained code does not establish this byte as an association-in-flight indicator.

When command `0x34` is skipped, the setter still calls `setIBSS(false)`, clears local driver/interface state at `+0x467`, `+0x468`, and `+0x404`, zeroes a six-byte local field at `+0x408`, and returns zero. If the command is entered, `_wlc_bsscfg_disable` has further gates before `_wlc_disassociate_client`; the setter ignores the resulting command status either way.

The child worker itself returns `-1` if `wlc+0x3b == 0` or `wlc+0x10e8 == 0` (`0x675a6..0x675b7`). It is not an acknowledgement that the interface had been associated, and the SET handler does not propagate that status.

## Decision

The evidence does **not** justify treating an all-zero/unavailable legacy BSSID as sufficient proof that SET22 is a valid no-op:

1. The GET_BSSID methods can skip their WLC query and leave output untouched when their state gates fail; zero-filled caller memory is not evidence that the child observed an all-zero BSSID.
2. 4331's skip byte is `cfg->associated`, but the setter does not check the separate `cfg+0x320` association context. Its own command-skip branch also bypasses the `bsscfg_down` path that invokes `_wlc_assoc_abort` for a nonzero association-context state.
3. 43224's predicate uses WLC lifecycle/AP flags and never inspects its current record. The observed `+0x3b` writes occur at scan-complete/join-adoption and after teardown, rather than being derived from the BSSID bytes.
4. Both child handlers return zero on skip and on ignored command failures, while still performing local resets. A zero SET return alone does not identify a no-op branch or prove the absence of an in-flight association.

The narrow conclusion is that both children have paths that skip command `0x34` and return zero. For 4331, `cfg->associated == 0` with the station-mode byte clear is a candidate *local skip* condition, but the binary does not close it into “already unassociated and no join in flight.” For 43224, the observed lifecycle predicate is not a current-network predicate. No cross-child no-current condition based on the BSSID getter, GET_STATE, or zero BSSID is proven by these samples.

## Exact bounds

This audit covers only the pinned El Cap provider and these two child binaries. It does not infer behavior for other driver versions, newer macOS providers, unpinned Broadcom devices, or runtime state not represented by the retained files. No production code, test, EFI, or driver state was modified.
