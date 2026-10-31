# Building AirportBrcmCompat

The source tree contains the Wi-Fi/private-address compatibility layer and the
native control/event bridge used by the 1.0.1-rc1 feature line. The runtime
build/UUID checks remain enabled.

## Requirements

- macOS with Xcode command-line tools (`xcrun clang`, `ld`, `nm`, and `codesign`).
- Python 3.9 or newer and Git.
- The kernel build resources pinned in
  [dependencies.lock.json](dependencies.lock.json).

The build targets **x86_64**. The compiler baseline used for the source
publication is Apple Clang 21.0.0. Different compilers can produce different
binaries; a matching version string alone is not proof of a matching build.

## Prepare the dependencies

From the repository root:

```sh
python3 tools/prepare_dependencies.py
```

This fetches exact upstream commits into the ignored `vendor/` directory and
prepares the required header/resource layout.
Existing dependency directories must match the lock file and be unmodified.
The full upstream checkouts retain their own licenses.

## Run the offline tests

```sh
python3 tools/run_tests.py
```

The public suite exercises the included core logic with synthetic inputs and
host-side adapters. It does not boot a kext, connect Wi-Fi, or perform AirDrop.
Private machine logs, linked Apple analysis binaries, deployment scripts, and
tests requiring those private inputs are not part of this suite.

## Build the two variants

RELEASE enables both exact system profiles, hotspot-scan adaptation and the
bounded SAE subset, without the optional receive-window diagnostics:

```sh
python3 tools/build_unified_kernel.py \
  --dual-profile-test-candidate --hotspot-scan-compat --sae-compat \
  --build-flavor RELEASE --output build/AirportBrcmCompat-RELEASE.zip
```

DEBUG additionally enables diagnostic compilation, baseline tracing and the
bounded receive windows:

```sh
python3 tools/build_unified_kernel.py \
  --dual-profile-test-candidate --hotspot-scan-compat --sae-compat \
  --baseline-trace --control-rx-windows \
  --build-flavor DEBUG --output build/AirportBrcmCompat-DEBUG.zip
```

Each output path must be new. The builder compiles, links, ad-hoc signs and
verifies one kext, checks its compiled module identity, and records source/file
hashes and feature flags in `build-manifest.json` inside the ZIP. These are
offline checks. The historical candidate flags do not authorize installation.

These commands never install a kext or edit EFI, NVRAM, or the system volume.
Use the release installation instructions only after reviewing the exact
artifact and retaining a working recovery path.

On 2026-10-31, both variants built with the pinned public dependencies and
Apple Clang 21.0.0 produced Mach-O executables byte-for-byte identical to the
existing 1.0.1-rc1 executables. Their SHA-256 values are recorded in
[release-metadata.json](release-metadata.json). This comparison covers the
core executables, not ZIP timestamps or manifests.

## Source layout

| Directory | Responsibility |
| --- | --- |
| `src/scan_kernel` | Scan/association adapters, kernel identity and build guards |
| `src/private_mac_compat` | Bounded private-address transactions and driver pins |
| `src/awdl_kernel` | Native control bridge, event ownership, routing and diagnostics |
| `src/awdl_compat` | Message codecs and bounded event-ring logic |
| `src/unified_kernel` | One-kext module identity and shared core |
| `tests` | Offline regression tests and synthetic fixtures |

`src/build_namespace.py` documents the separate namespace transformation used
for the legacy dependencies. It requires exact original binary inputs; those
Apple binaries are not source code and are not covered by this project's BSD
license. Rebuilding the core does not regenerate or replace the dependency ZIP.
The offline facade mock is never linked into the kext.
