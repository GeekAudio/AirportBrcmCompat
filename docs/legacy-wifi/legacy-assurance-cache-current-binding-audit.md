# Legacy assurance-history binding audit

Read-only review of the pinned El Cap provider and 4331/43224 child artifacts, reusing the existing scan-cache allocation, current-BSS producer, and lifetime audits. No production or test files were changed; no kext was loaded and no kernel path was executed.

## Finding

The provider scan-cache node and either child's current-BSS record are separate allocations with no retained pointer, operation token, or generation connecting them. A BSSID/SSID/content match is a network-level comparison only; it is not proof that the node is the object or observation that produced the current record. Therefore the provider `CacheKernel` allocation registry cannot provide CCX history for the old child current BSS.

This is expected for selective pruning: the bridge needs an owned current-network key to compare against provider-cache candidates. It must not read a matching provider node and promote it into current-BSS history.

## Two independent data paths

### Provider scan-cache path

For the fixed provider (`IO80211ElCap.bin`, SHA-256 `8ecd8f8a027d93205a493518c50a772f520ee774d2fa4d24b564dc67722c54b0`), `IO80211ScanManager::scanDone` obtains a child `apple80211_scan_result`, allocates its own `0xc0` cache node, copies the `0x98` result header, and separately allocates/copies the IE tail. The result source pointer is not stored in the node. The provider then inserts or replaces nodes through `updateCache`; its duplicate key is BSSID, and outstanding request references can keep detached old nodes alive. See `legacy-cache-allocation-provenance-audit.md` and `legacy-selective-cache-lifetime-audit.md`.

The two pinned children make another copy before the provider sees a result: `scanComplete` allocates/zeros result records and `scanConvertResult(wlc_bss_info*, apple80211_scan_result*)` copies fields and the IE tail into a separate result buffer/allocation; child `getSCAN_RESULT` returns that result to the provider. The provider cache node is therefore downstream of at least one data copy and has provider-managed lifetime/refcounts.

### Child current-BSS path

The 4331 current record is a heap record at `*(cfg+0x318)`; 43224's ordinary current record is inline at `wlc+0x2f8`. `_wlc_BSSinit` copies a selected child BSS record and its body into these destinations. On association completion, 4331 passes a selected target copy from `_wlc_assoc_scan_complete` (`0xb25d2` callsite); 43224 does the same at `_wlc_assoc_scan_complete` (`0x57e75`). These are child-side sources/stack copies, not provider cache-node pointers and not the provider's normalized `apple80211_scan_result` records. See `legacy-current-bss-internal-audit.md`, `legacy-bssinit-source-body-fallback-audit.md`, and `current-bss-ie-provenance-audit.md`.

The 4331 receive-refresh path has a distinct exact route: `_wlc_recvctl` calls `_wlc_recv_parse_bcn_prb` at `0x46c7b`, then passes the same stack output to `_wlc_BSSinit` at `0x46cdb`. The parser output has no IE pointer/length, so a bridge can only preserve the observed raw frame by staging an owned copy across that exact parser-to-BSSinit transaction and binding it to the committed current record. This path does not add a link to the provider cache node.

## Exact relation that is missing

The inspected routes expose no shared source pointer or scan-generation/request identifier from provider `scanDone`/child `getSCAN_RESULT` to the selected source passed by `_wlc_assoc_scan_complete` into `_wlc_BSSinit`. The provider node stores only copied result data and its own allocations; child BSSinit copies into a different current-record allocation. The provider's BSSID dedupe and the bridge's NetworkMatch predicate cannot reconstruct that missing provenance. Two observations with equal BSSID, SSID, capability, and IE bytes can still be different scan times and different objects.

To use a provider node as the actual history source, new binary evidence would need to prove one of these relations: (1) an exact shared object/source pointer survives both producer paths; or (2) a non-reused scan operation/generation token is propagated through child scan completion, provider result extraction, selected association-record construction, and current-record commit. No such field or direct relation is present in the audited paths.

## Shortest supportable old-stack integration point

Own assurance alongside the child current record, independent of provider scan-node ownership:

1. Admit only the pinned child’s exact association/current-record producer path. For full-body sources, capture the selected body before `_wlc_BSSinit`, call the original, then publish only after its exact target update and identity checks succeed. The known association callsites are 4331 `0xb25d2` and 43224 `0x57e75`; generic `_wlc_BSSinit` alone also serves candidate/AP/config paths and is too broad.
2. For 4331 bodyless receive refresh, bind a bounded copy of the raw frame and parser output to the exact parser callsite and one-shot `_wlc_BSSinit` call, then publish it only to the proven current-record target. This is the route already modeled by `BSSCapture::Registry` and `CurrentBSS::Binding` in the current kernel adapter; it is not derived from the provider cache.
3. Key committed data by child/WLC/config/current-record identity plus a non-reused generation, and invalidate on the audited current-record mutators/frees/teardown. Use the provider allocation registry only to prove provider node/IE ownership while enumerating/pruning candidate nodes.
4. If source ownership, target commit, writer coverage, or generation cannot be verified, keep Network Assurance `Unknown`. Do not promote a provider scan node that merely compares equal by BSSID or network identity.

This identifies a feasible current-record ownership boundary. It does not prove every old child writer is intercepted at runtime, nor that all scan/candidate/AP callers represent an associated station. Any activation must preserve the existing exact caller/config/target admission and fail closed on uncovered paths.

## Sources

- `legacy-cache-allocation-provenance-audit.md/.json`: provider node allocation, copy, update, dedupe, request-ref, and destructor provenance.
- `legacy-selective-cache-lifetime-audit.md`: provider node ownership and detached-node lifetime.
- `legacy-current-bss-internal-audit.md`: child current-record layouts and current pointer paths.
- `legacy-bssinit-source-body-fallback-audit.md`: current-record source callsites and branch limitations.
- `current-bss-ie-provenance-audit.md/.json`: full body and scan-result IE-tail formats; association source caveats.
- `src/legacy_wifi_compat/cache_kernel.cpp`: provider-only allocation registration at `updateCache`.
- `src/legacy_wifi_compat/disassociate_kernel.cpp`, `bss_capture.hpp`, `current_bss.hpp`: current-record capture/binding path, separate from provider cache-node registry.
