# Changelog

## 1.1.0 automatic compatibility candidate

- Replace host build/UUID allowlists with structural kernel-image validation and per-feature interface checks.
- Keep the bundled wireless-driver pins and strict scan, association and event data contracts.
- Admit matching interfaces independently of the system build number; reject incompatible kernel implementations before the affected routes are installed.
- Use Darwin 25 as the minimum with no fixed upper version in the matching Wi-Fi configuration snippets.
- Make optional receive diagnostics depend on bridge readiness rather than a named system build.

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
