# 4331 association-context pointer lifetime audit

Read-only audit of the retained El Capitan `AirPortBrcm4331.bin`. It checks the lifetime of the association context pointer at `bsscfg+0x320`, not the lifetime of every field or timer reachable through that object.

## Pinned input and method

- Binary: `build/research/oclp-legacy/elcap-analysis-inputs/AirPortBrcm4331.bin`
- SHA-256: `c5baef22eca03600ad255ac034d825d4a251b0538596a50ac92f845b2c86e62e`
- Symbolized listing: `build/research/oclp-legacy/elcap-analysis-inputs/4331-setSCAN_REQ_MULTIPLE.asm`
- Listing SHA-256: `87a20506c6a2e622aa3896dd105d858e6ca3bdb589c55372fb2fbdb194085e21`
- Scope: searched the full retained listing for memory operands based on `0x320(%...)`, then inspected the allocation, STA init/deinit/reinit, and config free functions and direct `_wlc_bsscfg_mfree` call sites. This is a bounded direct-code audit, not a complete indirect-call graph.

## Pointer allocation, reuse, and release

| Function | Evidence | Effect on `cfg+0x320` and owned allocation |
|---|---|---|
| `_wlc_bsscfg_malloc` `[0xb47e9,0xb49a9)` | `0xb4809` requests `0x60` bytes through `_wlc_calloc`; `0xb4816` stores returned pointer to `cfg+0x320`. `_wlc_calloc` `[0xb47bc,0xb47e8)` uses `_osl_malloc` then zeroes the allocation. | The context is allocated as a fixed `0x60`-byte child allocation alongside the cfg; it is not embedded in cfg. If any later cfg allocation fails, this function calls `_wlc_bsscfg_mfree` before returning null (`0xb499a`). |
| `_wlc_bsscfg_sta_init` `[0x5f02f,0x5f1fe)` | Loads `cfg+0x320` at `0x5f043`, then `_bzero(context,0x60)` at `0x5f077`. | Initializes/reinitializes the existing object. It does not store a new pointer into `cfg+0x320` or free the `0x60` object. |
| `_wlc_bsscfg_sta_deinit` `[0x5ee50,0x5eff8)` | Loads `cfg+0x320` at `0x5ee60`; frees context-owned timers and suballocations at `0x5ee74–0x5eecb`; no `osl_mfree(context,0x60)` and no store to `cfg+0x320` in this function. | Deinitializes resources held by the context while keeping the context allocation and cfg pointer alive. |
| `_wlc_bsscfg_reinit` `[0x5f1fe,0x5f2bd)` | Calls `_wlc_bsscfg_sta_deinit` at `0x5f22a` on the transition out of STA mode. The transition into STA mode calls `_wlc_bsscfg_sta_init` at `0x5f285`. | The context allocation is reused. STA init zeroes the existing `0x60` bytes; this is an in-place content mutation even though the pointer itself is unchanged. |
| `_wlc_bsscfg_mfree` `[0xb49a9,0xb4c43)` | Loads `cfg+0x320` at `0xb49e5`; frees context suballocations; frees the context itself with size `0x60` at `0xb4a3b`; only then clears `cfg+0x320` at `0xb4a40`. | This is the observed release of the context object. A reader cannot safely rely on seeing the cleared pointer before the free; the route must be excluded for the entire function. |
| `_wlc_bsscfg_free` `[0x5e6be,0x5e92d)` | Calls `_wlc_bsscfg_deinit` at `0x5e6ce`; on the heap-config path calls `_wlc_bsscfg_mfree` at `0x5e90a`, then removes the cfg table entry at `0x5e90f`. | Config destruction releases the context through `mfree`. The embedded primary cfg path skips heap-config release here and is ultimately handled by WLC detach cleanup. |
| `_wlc_detach_mfree` (entry `0xb5154`) | Calls `_wlc_bsscfg_mfree` for `wlc+0x360` at `0xb5209`. | WLC teardown also releases the primary cfg context through the same helper. |

The full listing contains only one nonzero pointer publication to `cfg+0x320` (`0xb4816`) and one zeroing store (`0xb4a40`). The only direct calls to `_wlc_bsscfg_mfree` found are allocation-failure cleanup (`0xb499a`), `_wlc_bsscfg_free` (`0x5e90a`), and `_wlc_detach_mfree` (`0xb5209`). I found no separate replacement or free of the `0x60` context while its cfg remains live.

## Gate and read safety

The normal selected provider route rejects an unrecognized caller unless controller and interface share a WorkLoop and `loop->inGate()` is true: `src/legacy_wifi_compat/legacy_install.cpp:309-322`. The cache binding check independently requires the retained manager, controller, interface, and timer to share that WorkLoop and gate: `legacy_install.cpp:170-192`.

The child’s known asynchronous timer/event path is attached to the controller WorkLoop:

- 4331 `_wlc_eventq_attach` at `0x80e79` registers `_wlc_timer_cb` and calls `_wl_init_timer` at `0x80edc`; `_wlc_timer_cb` invokes the registered callback. The association timer is initialized from `_wlc_bsscfg_sta_init` at `0x5f0c1–0x5f0db`.
- The previously audited 4331 `_wl_init_timer` at `0x55a4` gets the controller WorkLoop through vtable slot `+0x688`, creates an `IOTimerEventSource`, and adds it through slot `+0x140`.
- 43224 corroboration: `_wl_init_timer` at `0xe7d6` uses the same slots; its event queue attachment registers `_wlc_process_eventq` and calls the timer helper at `0xa5254–0xa52b7`.

For an idle-state read of `context+0x08/+0x0c`, the gate is the serialization condition for `sta_init`/`reinit` in-place zeroing and association state callbacks. The main memory fence protects cfg/context lifetime against the routed config-free and WLC teardown paths; it does not itself observe an in-place `sta_init`/`reinit`. Therefore the read must remain inside the checked gate, and the existing `CfgMfree`/`CfgFree`/WLC-stop mutation coverage must span their complete release bodies. A no-fault read or a post-read epoch check alone would not make the pointer safe.

## Conclusion and limits

For this pinned child, `cfg+0x320` is allocated with the cfg, reused (not replaced) across STA reinitialization, and released only through `_wlc_bsscfg_mfree` paths. There is no observed independent context free while cfg remains live. The bytes at `context+0x08/+0x0c` can still be rewritten in place by STA reinitialization; using them for idle admission depends on the verified WorkLoop gate, not pointer lifetime alone. This report does not establish the same layout or lifecycle for any other child build.
