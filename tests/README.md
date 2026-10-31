# Offline regression tests

Run the complete public suite from the repository root:

```sh
python3 tools/run_tests.py
```

Run one area, or combine areas:

```sh
python3 tools/run_tests.py --suite scan
python3 tools/run_tests.py --suite private-mac --suite awdl
python3 tools/run_tests.py --suite build
```

The suites require macOS, Python 3, and Xcode Command Line Tools (`xcrun`, Clang, and `nm`). They compile the checked-in production helpers and kernel components against synthetic inputs and host-side mocks. They do not need private driver images, research archives, EFI access, elevated privileges, a kernel load, or a Wi-Fi device. They cover scan adaptation and profile guards, private-address transaction policy (including disabled and candidate SAE handling), bounded event codecs, event ownership, queue lifecycle, numeric baseline tracing and control-RX windows, plus builder dependency-path/CLI behavior using synthetic SDK and Lilu directory fixtures.

These tests establish offline behavior of the exercised code paths. They do not establish that a particular macOS build boots the kext, that private kernel ABI pins match a new OS build, or that Wi-Fi, sleep/wake, roaming, Handoff, or AirDrop work on hardware. Those claims still require a separately recorded build-specific boot and feature test.
