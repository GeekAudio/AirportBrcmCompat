# Tahoe current-BSS Network Assurance freshness audit

Read-only static audit of the retained Tahoe 26.7.2 (25G332) BootKC. No kernel code was executed, no driver was loaded, and no production or test file was changed.

## Result

A new `IO80211BSSBeacon` data allocation begins with Network Assurance clear: `initWithChanSpec` allocates the `0x698`-byte BSS-data view through `IOMallocTypeImpl`, and the verified typed-allocation path applies `Z_ZERO`. The assurance byte is BSS-data `+0x53a`, bit 0. Therefore a newly-created beacon whose complete valid Beacon/Probe Response body has no matching CCX Network Assurance IE has value 0.

That does not establish that the current BSS is fresh. The normal `WCLNetManager::updateBss` route asks `WCLScanCacheStore::updateOrAddBeacon` for a beacon and passes that returned pointer into `setCurrentBSS`. The cache helper first attempts `IO80211ScanCacheStore::updateScanCache`; on a match, it removes and returns the existing beacon object, then calls `setBeaconDataFromMsg` on that same object. The parser has no unconditional reset of `+0x53a`; if the new body lacks a valid matching CCX IE, the old value persists. The same object can consequently become the current BSS with a prior `true` bit even though its latest body has no CCX IE.

An owned-history implementation for this Tahoe native object is feasible only if it binds state to that object's lifetime, not merely to the current body or network name: initialize `Disabled` for a proven fresh data object; on each fully observed parse, replace state with the last valid matching CCX value when one is present, and preserve the prior value when no valid matching item writes the native field; bind the resulting object identity to the exact pointer passed to `setCurrentBSS`. Any object already alive before observation starts, any missed parse/lifecycle event, or pointer reuse without a generation/retirement proof remains `Unknown`.

This is Tahoe's native `IO80211BSSBeacon` / `WCLBSSBeacon` path. The AirportBrcmCompat project also audits an OCLP El Cap stack whose child current record and scan-cache nodes are different layouts and allocations. Their addresses must not be treated as these native beacon object identities. A portable legacy-stack history needs separate evidence for legacy cache-node creation, in-place update, match identity, eviction/destruction, and the exact current-record pointer/source binding. Until those lifecycle links are proven and covered, do not convert a missing CCX element in an El Cap current body into `Disabled`; keep it `Unknown`. This audit does not establish that the project currently hooks every native or legacy allocation/parse/destruction path, so it does not authorize treating all absent-IE cases as false.

## Evidence path

1. `WCLBSSBeacon::fromBeaconData` allocates the wrapper, calls `IO80211BSSBeacon::initWithChanSpec`, then calls `setBeaconDataFromMsg` with the incoming metadata and body. The init method stores a fresh BSS-data allocation at beacon `+0x10`; the allocation is `0x698` bytes and has the zero-allocation flag, as recorded in `legacy-reason-feature-gates-audit.md`.
2. In `setBeaconDataEx`, entry stores zero to `+0x53b` (adjacent byte), not `+0x53a`. A valid matching CCX subtype `0x0b` with body length at least five writes bit 0 of `+0x53a` from IE byte `+6` bit 7. Later valid matching entries overwrite earlier ones. No valid match means no store to `+0x53a`.
3. `IO80211ScanCacheStore::updateScanCache` obtains an existing beacon from `removeAndReturnObjectBasedOnFilter` and invokes `setBeaconDataFromMsg` on that same object. It does not allocate a new BSS-data block or clear `+0x53a`. Its caller `IO80211ScanCacheStore::updateOrAddBeacon` invokes the new-object factory only when the update path returns no matching object.
4. `WCLScanCacheStore::updateOrAddBeaconInternal` passes its factory to the native update-or-add method; the factory calls `WCLBSSBeacon::fromBeaconData` for a new object. `WCLNetManager::updateBss` calls the WCL helper, retains its returned pointer in `r12`, and passes that pointer to `WCLNetManager::setCurrentBSS`. The WCL setter forwards it unchanged to `WCLBssManager::setCurrentBSS`, which stores it in the current-BSS slot.

This establishes the Tahoe native current-object provenance and cache-reuse possibility. It does not prove every association transition uses this precise update path, nor does it provide a safe lifecycle hook or generation scheme for a bridge to observe objects that predate installation. It also does not establish object correspondence with any OCLP El Cap child current record or cache node. A minimum legacy implementation would need its own proven create/update/match/evict lifecycle and pointer-generation mapping before it could own history; this report supplies none of those legacy links.

## Exact sample and function spans

Source: `/System/Library/KernelCollections/BootKernelExtensions.kc`, Tahoe 26.7.2 / build 25G332, member `com.apple.iokit.IO80211Family`, BootKC SHA-256 `96c12f421a8e99580b5015dfd39877df38ecde9b9e056b8ccd28f15847bca35c`.

| Function | Member address | Size | SHA-256 |
|---|---:|---:|---|
| `IO80211BSSBeacon::initWithChanSpec` | `0x22db658` | 794 | `eb39a48f4c5b8bb572d355f4fe0fe2655de9dd7e316e298b5acb3196384eebb3` |
| `WCLBSSBeacon::fromBeaconData` | `0x218c9a2` | 202 | `aded9dcac9eaeeba88e30588e92359d3582cd332c5359c5ac6e588129c16fb0e` |
| `IO80211BSSBeacon::setBeaconDataFromMsg` | `0x22d910e` | 884 | `70eef871f93f23e12c08fead093f8afffc9a2336de56951d7dedbb31c47cd44c` |
| `IO80211BSSBeacon::setBeaconDataEx` | `0x22d9632` | 6006 | `78d979afccbd0ff6a5142e94857915b32be3c5b4f2d33a3a511a41ecef9b84b2` |
| `IO80211ScanCacheStore::updateOrAddBeacon` | `0x22d3674` | 386 | `e0ca83d1cd226dea9dd491f52e07e169e0a8dbca4d8d93106ae1dd8dae4cd0c6` |
| `IO80211ScanCacheStore::updateScanCache` | `0x22d3804` | 452 | `a8466f35eba3073e7555b6edacd2b1b0941b852961d14f584908b2c56a963c5c` |
| `updateScanCache` filter block | `0x22d3b7e` | 152 | `6155522baa70430ac92e63c9cb0003cbaaeecfd02209d97b10a9f23d2dec382c` |
| `WCLScanCacheStore::updateOrAddBeacon` | `0x2353fca` | 190 | `3b14f7a037ce95c402d1eb18373aa80f7ec42d9b443b4bfe7599357bf86b16f8` |
| `WCLScanCacheStore::updateOrAddBeaconInternal` | `0x2354088` | 231 | `a6f5c59d6aa41648701577c570a1e74af3d4c437cc8b1f386498cc3226a414b8` |
| `WCLNetManager::updateBss` | `0x2191924` | 712 | `22edc9a694f982596f8e6505af309406470c5d3c2b2888b611d5b4d6e85ed94d` |
| `WCLNetManager::setCurrentBSS` | `0x219397c` | 1714 | `511d1e7240e129b6f72456090a500d4b64f972484f95a42d78eec3ecc66b3460` |
| `WCLBssManager::setCurrentBSS` | `0x218cf44` | 70 | `987fc1887ae79bd7778e90c7764c1b7799f1a135653022334ff9ea159bc90cfb` |
| `isNwAssuranceEnabledInCCXIE` | `0x22dd922` | 18 | `dbd7aa5a9c7367d5a9379533e66a17477266b445f28982ced857efd9e38a6987` |

Supporting parser/cache artifacts are recorded in `legacy-reason-feature-gates-audit.md`, `legacy-reason-feature-gates-audit.json`, and their retained `.asm` files. The zero-initialized allocation evidence relies on the same report's BootKC allocator call-chain review and XNU `Z_ZERO` definition.
