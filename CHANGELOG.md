# Changelog

## 1.1.0 — 2026-11-01

- Replace host build/UUID allowlists with structural kernel-image validation and per-feature interface checks.
- Keep the bundled wireless-driver pins and strict scan, association and event data contracts.
- Admit matching interfaces independently of the system build number; reject incompatible kernel implementations before the affected routes are installed.
- Start the candidate at Darwin 23, selecting verified request and kernel contracts without a fixed host version ceiling.
- Add Sonoma/Sequoia scan, capability, association and native driver-version reply formats, preserving strict bounds and authentication fields.
- Bind compatibility work to the actual Broadcom primary interface instead of requiring `en1`.
- Generate separate NIC dependency variants and combine them into one EFI package with automatic selection at Darwin 25.
- Add optional upstream NIC matching for three additional modern NIC PCI IDs, restricting both PCI personalities to the modern NIC families.
- Extend the bounded SAE password carrier to Sonoma's 856-byte request and keep GET12 capability adaptation within its 64-bit request ABI.
- Verify anonymous ifnet call and data targets with bounded semantic checks when an exact saved layout does not match.
- Add a public ioctl and native callback scope fallback for kernel layout changes, with exact request identity, one-shot admission and checked route installation.
- Independently verify all three system dependency samples and both NIC variants; require complete scan request envelopes.
- Remove the unconnected recovery codec from source, tests and packaged binaries.
- Make optional receive diagnostics depend on bridge readiness rather than a named system build.
- Remove the unused RunAction fingerprint contract while preserving active synchronous lifecycle checks.
- Add macOS Intel CI with pinned external samples, zero-skip test enforcement and RELEASE/DEBUG builds.
- Resolve Clang through xcrun, PATH and system tools, including a C++ driver alias fallback.
- Provide offline package probing, configuration-copy merging, EFI preflight and privacy-filtered collection tools in the source repository.
- Limit installation ZIPs to kext bundles and configuration files; provide manifests and license notices as separate release attachments.
- Add illustrated installation instructions with a collapsible English translation.

## Source publication

- Publish the compatibility core, offline regression tests and build tools under BSD-3-Clause.
- Pin public build dependencies and remove workstation-specific build paths.
- Document RELEASE/DEBUG feature flags and distinguish offline checks from hardware validation.
- Keep the existing 1.0.1-rc1 core binaries and system-build guards unchanged.
- Package only the three customized wireless dependencies and Wi-Fi configuration snippets.

## 1.0.1-rc1 — 2026-10-28

- Add exact 25G332 compatibility alongside 25G241.
- Add hotspot-scan adaptation and a bounded SAE authentication subset.
- Provide separate RELEASE/DEBUG cores and the dependency/configuration package.
- Record the Test023r2 bidirectional AirDrop baseline.

## 1.0 — 2026-10-25

- Publish the 25G241/BCM43602 baseline and installation dependencies.
