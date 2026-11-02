# Building AirportBrcmCompat

The source tree builds **1.1.0** with `--release`. The
Wi-Fi/private-address adapters and native control/event bridge check actual
kernel interfaces instead of maintaining a host build-number/UUID allowlist.
An unqualified build remains an explicit development candidate; release builds
retain the same strict interface checks and report their validation scope.

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
python3 tools/prepare_test_fixtures.py
python3 tools/prepare_runtime.py
python3 tools/run_tests.py --require-all
```

The public suite exercises the included core logic with synthetic inputs and
host-side adapters. It does not boot a kext, connect Wi-Fi, or perform AirDrop.
`tests/fixtures.lock.json` pins the four small archives needed by the external
dependency checks. They are downloaded into ignored `build/`; no full system
images or private machine logs are needed. CI prepares these inputs and the
locked build resources on macOS 15/26 Intel, then rejects any skipped test.

## Build the two variants

RELEASE enables automatic interface checks, hotspot-scan adaptation and the
bounded SAE subset, without the optional receive-window diagnostics:

```sh
python3 tools/build_unified_kernel.py \
  --release \
  --build-flavor RELEASE --output build/AirportBrcmCompat-RELEASE.zip
```

DEBUG additionally enables diagnostic compilation, baseline tracing and the
bounded receive windows:

```sh
python3 tools/build_unified_kernel.py \
  --release \
  --baseline-trace --control-rx-windows \
  --build-flavor DEBUG --output build/AirportBrcmCompat-DEBUG.zip
```

Each output path must be new. The builder compiles, links, ad-hoc signs and
verifies one kext, checks its compiled module identity, and records source/file
hashes and feature flags in `build-manifest.json` inside the ZIP. These are
offline checks. Configuration snippets in this source tree match 1.1.0.

These commands never install a kext or edit EFI, NVRAM, or the system volume.
Use the release installation instructions only after reviewing the exact
artifact and retaining a working recovery path.

CI prepares one shared dependency set from the three locked sample archives,
checks the complete DMA-compatible NIC image and its unchanged imports/vtables,
then builds two complete installation ZIPs. Each contains flat kext bundles in
`Kexts/` and a `config.plist` fragment. `tools/package_release.py` keeps build
manifests, per-member hashes, provenance and notices under `metadata/` outside
the installation ZIPs. Only the RELEASE and DEBUG ZIPs are Release assets;
checksums and links to source evidence/notices belong in the Release notes.
See [tools/README.md](tools/README.md).

The external inventory separates the immutable release tag, core binary/build identity, and repackaging checkout. Member hashes and installation paths can be checked with `brcmctl.py verify`; see [release verification](docs/RELEASE-VERIFICATION.md). CI checks hardware-record structure without executing or claiming hardware tests.

[release-metadata.json](release-metadata.json) records the bundled 1.1.0
release cores and their offline checks. Each fresh build carries its own
manifest and hashes. The earlier 1.0.1-rc1 artifacts remain associated with
their release tag.

## Compatibility policy

The compatibility core, modern NIC dependencies and the optional third-party
NIC injector start at Darwin 23. The core has no fixed maximum.
The boot environment and underlying dependencies must themselves support the
target system. An absent version ceiling is not proof of support.

The running inner kernel must have a valid bounded x86_64 Mach-O header and a
unique nonzero UUID. The UUID is remembered only to detect a contradictory image
during the same run; new UUIDs do not require a source change. Structural image
validation does not approve a private interface.

The offline ifnet verifier accepts BootKC files with `--kernel-collection` and
standalone KDK kernels with `--kernel-image`. The input kind is explicit and is
recorded in the report. A standalone kernel can check an instruction contract;
it does not establish that a retail system's BootKC contains that same image.

Image validation owns its bounded header snapshot. It does not allocate or read
framework-private Mach-O objects. Before calling the runtime-resolved XNU
no-fault reader, the symbol source must agree with the loader-resolved `IOLog`
and `IOSleep` imports. A stale standalone-kernel/collection symbol view is
rejected. Header reads must complete in full, and candidate ranges must satisfy
both segment permissions and a bounded no-fault mapping probe. The XNU reader
is still a private interface; a missing symbol disables admission.

The reproducible build uses resource revisions pinned in the dependency lock.
Runtime interface admission is checked separately from the build resources.

Each dependent installer checks its resolved kernel symbols, executable ranges
and implementation contracts before routing. The supplied wireless binaries
retain their own UUID, layout, instruction and call-target checks. These fixed
dependency pins are independent of the host OS build.

The private-address callback contract hashes its complete bounded function
body. Only listed relative-address operands are normalized;
branches, argument registers, stack slots, field offsets and reference-count
instructions remain part of the fingerprint. Named helper targets are resolved
separately. Two adjacent-data references also require their exact relationship
to a resolved linker anchor; this is a layout check, not an interpretation of
that symbol as a public data structure. Saved exact-layout fingerprints remain
available without extra target excerpts. A second path permits five relocated
panic-helper/string references only after bounded no-fault reads verify their
complete checked instruction sequences, literals and independently resolved
panic callee. The callback body is still hashed; the remaining anonymous
post-release displacement stays in that fingerprint. It is not justified by a
nearby unrelated symbol or a short code prefix. Missing auxiliary evidence,
changed fields or unknown target content reject this second path.
These checks recognize the implemented contracts; they cannot infer the meaning
of a new private kernel ABI.

If these saved kernel implementations do not match, a second lifetime path can
use the public `ifnet_ioctl` boundary. Its resolved address must match the
loader import, and its copied trampoline prefix must contain only admitted
position-independent instructions. The native `IONetworkInterface` registration
and ioctl callback must satisfy complete instruction contracts, including
independently resolved calls and the fixed wireless `performCommand` consumer.
The callback contract has no host UUID or build-number condition.

This path keeps opaque request identities in nested, synchronous scopes. Only
the same thread, interface, command and data pointer can claim one callback and
one perform operation. Reentry, mismatches, repeated claims and exhausted
registries revoke admission. The original public KPI still owns the I/O
reference; the scopes neither acquire an ordinary reference nor extend the
callback lifetime. Existing credential, primary-interface, controller-gate and
private-state checks remain required. This tolerates internal kernel layout
changes while the public KPI and checked interface callback stay compatible;
it does not infer an unknown callback or request schema.

The callback checker recognizes independently inspected implementations
from Sonoma, Sequoia and Tahoe. Selection uses their full code contracts and resolved
symbols, without checking an OS label or UUID. These additional contracts alone
do not prove whole-system support. To check explicitly supplied Apple
kernel collections against the production validators:

```sh
python3 tools/verify_ifnet_kernel_contracts.py \
  --kernel-collection /path/to/BootKernelExtensions.kc \
  --output build/ifnet-contracts.json
```

Repeat `--kernel-collection` for multiple samples. The verifier checks real
file-backed bytes, symbol targets, callback offsets and mapped ranges, then
tests byte mutations, incorrect targets and address relocation. Apple samples
are supplied locally and are not included in the source repository.

Add `--save-excerpts build/ifnet-excerpts` with a new output directory to retain
the bounded function bytes and symbol/segment metadata after successful image
verification. After removing the large input images, the production validators
can be rerun with `--contract-excerpt build/ifnet-excerpts/BootKC1.json` (repeat
for multiple excerpts). Replay reports explicitly mark the original image as
not reverified: they check the retained bytes against the current contracts,
without re-extracting symbols or authenticating the recorded source hash.

The owned-client reset uses its retained synchronous work-loop/gate scope,
checking thread, owner, provider, gate binding and one-shot consumption.
It retains the supplied wireless driver's UUID and instruction guards without
pinning the host command-gate function body or its internal return offset.

Request adapters retain their exact lengths, version fields, allowed values and
bounded copies. Unknown layouts are rejected or passed to the original handler
without conversion. Code or protocol changes can still require a new adapter;
matching interfaces can continue across system updates without a version entry.

The source now dispatches the observed scan-result sizes 1228/2264/2272,
capability buffers 16/19/21 and association inputs 856/900/908. The 856-byte
association path preserves the original authentication fields and admits
open/WPA2 and the enabled SAE password subset, with no nonzero extension or grouping scope. The
900-byte path normalizes only the verified reserved tail in an owned copy;
the shared validator retains all other restrictions. These codecs do not by
themselves approve every minor release. The native control bridge also accepts
the verified 256-byte inline GET43 response alongside the original 384-byte
response; its existing out-of-line route remains limited to 384 bytes.

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

`src/build_namespace.py` performs the namespace transformation for the modern
wireless dependencies. It requires exact original binary inputs; those Apple
binaries are not source code and are not covered by this project's BSD license.
Rebuilding the core does not regenerate or replace the dependency ZIP.
The offline facade mock is never linked into the kext.

## Wi-Fi dependency profiles

The source fixtures preserve the original profiles so old evidence remains
reproducible. They are inputs to validation, not separate installation options.
The current installer contains one `AirPortBrcmNIC.kext` and one common set of
other dependencies. All entries start at Darwin 23 and have no maximum.

```sh
python3 tools/prepare_test_fixtures.py
python3 tools/prepare_runtime.py
python3 tools/unify_wifi_dependencies.py \
  --sonoma build/compatibility-profiles/sonoma14-dependencies.zip \
  --sequoia build/compatibility-profiles/sequoia15-dependencies.zip \
  --tahoe build/compatibility-profiles/tahoe26-dependencies.zip \
  --output build/ci-dependencies.zip
python3 tools/prepare_broadcom_injector.py \
  --archive build/research/AirportBrcmFixup-2.2.1-RELEASE.zip \
  --dependency-profile automatic --output build/ci-additional.zip
```

`unify_wifi_dependencies.py` verifies all three original archives, their sample
provenance, equal common dependencies and signatures. It selects the complete
DMA-compatible NIC image, renaming its folder without modifying code. The
static verifier checks every changed byte range against the original image,
branch targets, helper calls, all imports and vtables. The private-driver pin
checks continue to use the exact shipped image. No code is rewritten while the
NIC is running. See [the architecture and evidence scope](docs/ARCHITECTURE.md).

The final packager flattens the upstream NIC injector and signs its parent
again, checking that executable sections did not change. It includes the
pinned runtime dependency, preserving its x86_64 executable sections. All
components have independent identities and the generated configuration gives
one dependency order for every target OS. The installer preserves an existing
compatible runtime dependency used by unrelated kexts.

PCI matching and static ABI checks do not establish DMA lifetime, hardware
operation, or compatibility with a future system. The combined NIC's behavior
on Sonoma and Sequoia still needs hardware evidence. Original profile builders
and their tests remain available to audit the older samples; their split
archives are never shipped by the current packager.
