# Offline regression tests

Run the complete public suite from the repository root:

```sh
python3 tools/prepare_dependencies.py
python3 tools/prepare_test_fixtures.py
python3 tools/prepare_runtime.py
python3 tools/run_tests.py --require-all
```

Run one area, or combine areas:

```sh
python3 tools/run_tests.py --suite scan
python3 tools/run_tests.py --suite private-mac --suite awdl
python3 tools/run_tests.py --suite build
```

The suites require macOS, Python 3, and Clang/`nm` from Xcode Command Line Tools. The runner tries xcrun, PATH and system tools, and supplies a named C++ driver alias when only clang is exposed. It restores PATH after completion. Tests compile the checked-in production helpers and kernel components against synthetic inputs and host-side mocks. They cover scan and association adaptation, private-address transactions, bounded event codecs, event ownership, queue lifecycle, numeric diagnostics and builder behavior.

The external checks use three hash-pinned Sonoma/Sequoia/Tahoe dependency ZIPs and the official optional-component release ZIP, plus the locked build resources. `tests/fixtures.lock.json` records the sample hashes. The original 323-test suite had ten tests requiring these external inputs/resources; new regression cases also use them. CI prepares every input and runs `--require-all`, so a missing sample or skipped test fails the job. A plain `run_tests.py` remains available for a partial local run and reports skips normally.

The CI matrix runs both tests and RELEASE/DEBUG builds on `macos-15-intel` and `macos-26-intel`, with logs and signed ZIPs retained as artifacts. No EFI access, elevated privileges, kernel load or Wi-Fi device is used.

These tests establish offline behavior of the exercised code paths. They do not establish that a particular macOS build boots the kext, that private kernel ABI pins match a new OS build, or that Wi-Fi, sleep/wake, roaming, Handoff, or AirDrop work on hardware. Those claims still require a separately recorded build-specific boot and feature test.

The runtime-record and diagnostic tests are synthetic host-side checks. They reject mismatched PCI/build/core/boot evidence, sender-only AirDrop claims, unknown diagnostic stages and inconsistent inventories. They do not count as hardware-matrix runs. The matrix currently contains no current-release hardware results.

Unified delivery tests rebuild the common dependency set, compare the actual
RELEASE/DEBUG configuration and payloads, check signatures and one NIC path on
every target generation, and reject altered runtime inputs. Installer tests
use temporary EFI copies for preview, migration, backup, rollback, concurrent
changes and preservation of unrelated configuration. DMA static checks do not
establish DMA lifetime or hardware behavior on the older target systems.

Upgrade checks replay the production public-KPI prefix and networking callback validators against synthetic x86_64 BootKC inputs, including future Darwin numbers and new UUIDs. Wrong architectures, mismatched actual versions, missing symbols, changed callbacks and incorrect relocation targets must refuse. Both shipping fragments retain one active NIC on future targets. These tests prepare the macOS 27 Intel-port workflow; they are not macOS 27 samples or runtime support. See [upgrade preparation](../docs/MACOS-27-PREPARATION.md).
