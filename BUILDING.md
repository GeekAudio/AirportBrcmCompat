# Building AirportBrcmCompat

The source tree builds the **1.1.0 automatic compatibility candidate**. The
Wi-Fi/private-address adapters and native control/event bridge check actual
kernel interfaces instead of maintaining a host build-number/UUID allowlist.
The published 1.0.1-rc1 downloads remain separate artifacts.

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

RELEASE enables automatic interface checks, hotspot-scan adaptation and the
bounded SAE subset, without the optional receive-window diagnostics:

```sh
python3 tools/build_unified_kernel.py \
  --automatic-compatibility \
  --build-flavor RELEASE --output build/AirportBrcmCompat-RELEASE.zip
```

DEBUG additionally enables diagnostic compilation, baseline tracing and the
bounded receive windows:

```sh
python3 tools/build_unified_kernel.py \
  --automatic-compatibility \
  --baseline-trace --control-rx-windows \
  --build-flavor DEBUG --output build/AirportBrcmCompat-DEBUG.zip
```

Each output path must be new. The builder compiles, links, ad-hoc signs and
verifies one kext, checks its compiled module identity, and records source/file
hashes and feature flags in `build-manifest.json` inside the ZIP. These are
offline checks. Configuration snippets in this source tree match this candidate.

These commands never install a kext or edit EFI, NVRAM, or the system volume.
Use the release installation instructions only after reviewing the exact
artifact and retaining a working recovery path.

[release-metadata.json](release-metadata.json) records the bundled 1.1.0
candidate cores and their offline checks. Each fresh build carries its own
manifest and hashes. The earlier 1.0.1-rc1 artifacts remain associated with
their release tag.

## Compatibility policy

The minimum is Darwin 25; the plugin and matching OpenCore snippets have no
fixed maximum. The boot environment and underlying dependencies must themselves
support the target system. An absent version ceiling is not proof of support.

The running inner kernel must have a valid bounded x86_64 Mach-O header and a
unique nonzero UUID. The UUID is remembered only to detect a contradictory image
during the same run; new UUIDs do not require a source change. Structural image
validation does not approve a private interface.

Each dependent installer checks its resolved kernel symbols, executable ranges
and implementation contracts before routing. The supplied wireless binaries
retain their own UUID, layout, instruction and call-target checks. These fixed
dependency pins are independent of the host OS build.

The private-address callback and command-gate reset contracts hash complete
bounded function bodies. Only listed relative-address operands are normalized;
branches, argument registers, stack slots, field offsets and reference-count
instructions remain part of the fingerprint. Named helper targets are resolved
separately. Two adjacent-data references also require their exact relationship
to a resolved linker anchor; this is a layout check, not an interpretation of
that symbol as a public data structure. Anonymous cold/post-release displacements remain in the fingerprint,
and their targets are checked for the required mapping permissions. They are
not tied to a nearby unrelated symbol. Changes to these anonymous layouts can
disable the private-address adapter even when named interfaces still match.
These checks recognize the implemented contracts; they cannot infer the meaning
of a new private kernel ABI.

Request adapters retain their exact lengths, version fields, allowed values and
bounded copies. Unknown layouts are rejected or passed to the original handler
without conversion. Code or protocol changes can still require a new adapter;
matching interfaces can continue across system updates without a version entry.

Optional DEBUG receive diagnostics follow the admitted bridge and owned message
format. Their IORegistry key is `BroadcomAwdlBaseline`, without a build suffix.

## Source layout

| Directory | Responsibility |
| --- | --- |
| `src/scan_kernel` | Scan/association adapters, structural image validation and interface contracts |
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
