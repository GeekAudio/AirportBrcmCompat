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

CI also combines the three locked dependency samples, prepares the optional
modern-card package and runs `tools/package_release.py`. The resulting four
versioned installation ZIPs contain only kext bundles and configuration
fragments. `VALIDATION.json` retains the full input manifests, test result,
source commit and delivered hashes. `LICENSES.md` and `SHA256SUMS.txt` accompany
the downloads separately. Offline configuration/preflight tools remain in the
source repository. See [tools/README.md](tools/README.md).

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

The namespace builder accepts the pinned original wireless inputs and an
explicit native Skywalk sample. It can read a native fileset member directly
from a kernel collection, including systems whose on-disk kext lacks its binary:

```sh
python3 src/build_namespace.py \
  --legacy-dir /path/to/original-wireless-kexts \
  --dependency-profile sonoma-sequoia \
  --native-kernel-collection /path/to/BootKernelExtensions.kc \
  --output build/WiFi-Dependencies-Sonoma-Sequoia.zip
```

Build the independent Sequoia input with the same pinned dependency directory
and profile, but use the Sequoia BootKC and a separate output path:

```sh
python3 src/build_namespace.py \
  --legacy-dir /path/to/original-wireless-kexts \
  --dependency-profile sonoma-sequoia \
  --native-kernel-collection /path/to/Sequoia/BootKernelExtensions.kc \
  --output build/WiFi-Dependencies-Sequoia.zip
```

`sonoma-sequoia` selects the original nested AirPortBrcmNIC for Darwin 23–24.
`tahoe` selects the separate AirPortBrcmNIC-Tahoe input for Darwin 25 onward.
Each output contains three Wi-Fi dependencies and a matching configuration
fragment. The manifest records the actual collision-check sample and input
hashes. Dependency selection is separate from core protocol compatibility;
these profiles are development candidates, not an expanded support claim.

To prepare both NIC variants in one EFI dependency package:

```sh
python3 tools/combine_wifi_dependency_profiles.py \
  --sonoma-sequoia build/WiFi-Dependencies-Sonoma-Sequoia.zip \
  --sequoia build/WiFi-Dependencies-Sequoia.zip \
  --tahoe build/WiFi-Dependencies-Tahoe.zip \
  --output build/WiFi-Dependencies-Automatic.zip
```

All three inputs are required. The combiner verifies the pinned Sonoma,
Sequoia and Tahoe sample hashes as offline provenance and collision-check
evidence; these are not runtime OS-version or kernel-UUID admission rules. It
then requires the Sonoma and Sequoia shared
dependencies and NIC payload to match byte-for-byte. It records all three
sample hashes in the output manifest, deriving the Sequoia version/build from
its pinned sample hash rather than its input label. The fragment still loads
one NIC variant for Darwin 23–24 and the other from Darwin 25 onward; both
variants are stored in EFI, and only one is loaded for a given system. The
compatibility core is a separate download/build. This package contains no
Bluetooth or system-volume patching components.

To recheck that the bundled Sonoma/Sequoia and Tahoe NIC binaries satisfy the
current private-driver pin contract without loading a kext or calling a driver
function:

```sh
python3 tools/verify_modern_driver_pins.py \
  --dependencies build/WiFi-Dependencies-Sonoma-Sequoia.zip \
  --dependencies build/WiFi-Dependencies-Sequoia.zip \
  --dependencies build/WiFi-Dependencies-Tahoe.zip \
  --output-json build/research/modern-driver-pins-verification.json
```

This is an offline host check of the actual `initializeDriverPins` code. The
tool maps each Mach-O by its load-command segment addresses, checks all six
modern IDs against the actual device table and its lookup/success path, reports the
dependency and executable hashes, and rejects conflicting same-profile
executables. It does not change runtime OS selection.

For the additional modern NIC PCI IDs `4357`, `43b1` and `43b2`,
prepare the optional upstream core and NIC injector from the
[official 2.2.1 RELEASE ZIP](https://github.com/acidanthera/AirportBrcmFixup/releases/download/2.2.1/AirportBrcmFixup-2.2.1-RELEASE.zip):

```sh
python3 tools/prepare_broadcom_injector.py \
  --archive /path/to/AirportBrcmFixup-2.2.1-RELEASE.zip \
  --dependency-profile sonoma-sequoia \
  --output build/Additional-Broadcom-Cards.zip
```

The tool verifies the upstream archive hash, keeps the NIC injector, and
excludes the injector for the different AirPortBrcm4360 driver. Its fragment
restricts both the core PCI personality and child injector to the three native
NIC IDs and three third-party NIC IDs. The upstream executable sections remain
unchanged; only the matching plists are narrowed and re-signed. Its fragment
adds only the optional Wi-Fi components. PCI matching does not establish
hardware functionality; use the same profile as the main dependency package.
For a combined cross-version dependency package, select `automatic`; its two
optional entries start at Darwin 23. The upstream component's own runtime
compatibility checks still apply.
