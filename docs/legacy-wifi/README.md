# Parked legacy Wi-Fi compatibility work

This branch preserves the unfinished IO80211ElCap / AirPortBrcm4331 / AppleAirPortBrcm43224 implementation. Development was parked at the user’s request on 2026-11-01; it is excluded from main and is not a supported release. Modern AirPortBrcmNIC dependencies are a separate path.

The archived checkpoint records 410 passing offline tests and RELEASE/DEBUG builds for the mixed development tree. It does not establish runtime, hardware, or complete operating-system coverage. Generated binaries, system samples and large downloads are not committed here.

See `compat-disassociate-next-steps.md` for the implementation handoff, and `compat-disassociate-idle-validation.json` for the source and research hashes. The handoff’s original goal/commit instructions describe the earlier checkpoint only and were superseded by the decision to park this work. In-flight association cancellation, current-network assurance history and broader runtime validation remain unfinished.

Resume future work on this branch and rebase or merge deliberately against the modern main line; do not reintroduce this stack through a routine main merge.
