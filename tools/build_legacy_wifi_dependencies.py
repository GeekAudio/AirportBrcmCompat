#!/usr/bin/env python3
"""Build a pinned EFI-only OCLP legacy Wi-Fi dependency package."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import zipfile

from legacy_wifi_dependency_builder import PROFILES, prepare


def parse_assignment(value: str) -> tuple[str, Path]:
    label, separator, path = value.partition("=")
    if not separator or not label or not path:
        raise argparse.ArgumentTypeError("expected LABEL=PATH")
    return label, Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--io80211-archive", type=Path, required=True,
                        help="pinned OCLP IO80211ElCap v2.0.1 ZIP")
    parser.add_argument("--corecapture-archive", type=Path, required=True,
                        help="pinned OCLP corecaptureElCap v1.0.2 ZIP")
    parser.add_argument("--kernel-collection", type=parse_assignment, action="append",
                        default=[], metavar="Darwin21|Darwin22|Darwin23|Darwin24|Darwin25=PATH",
                        help="user-selected official target BootKC for class-collision checks; supply one or more, repeat as needed")
    parser.add_argument("--dependency-profile", choices=PROFILES,
                        default="legacy-darwin21plus")
    parser.add_argument("--output", type=Path, required=True,
                        help="new .zip output path; existing files are never overwritten")
    parser.add_argument("--nm", default="nm", help="Apple nm executable")
    args = parser.parse_args(argv)
    try:
        manifest = prepare(args.io80211_archive, args.corecapture_archive,
                           args.output, args.kernel_collection,
                           args.dependency_profile, args.nm)
    except (OSError, ValueError, KeyError, zipfile.BadZipFile,
            subprocess.CalledProcessError) as error:
        parser.exit(1, f"build_legacy_wifi_dependencies: {error}\n")
    print(json.dumps({"output": str(args.output.resolve()),
                      "status": manifest["status"]}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
