#!/usr/bin/env python3
"""Fetch pinned build dependencies into vendor/. Does not install any kext."""
import json
from pathlib import Path
import shutil
import subprocess

PROJECT = Path(__file__).resolve().parents[1]


def git(*args):
    return subprocess.run(["git", *map(str, args)], check=True,
                          stdout=subprocess.PIPE, text=True, timeout=300).stdout.strip()


def checkout(name, spec, directory):
    if directory.exists():
        if (directory.is_symlink() or not (directory / ".git").is_dir() or
                git("-C", directory, "rev-parse", "HEAD") != spec["commit"] or
                git("-C", directory, "status", "--porcelain", "--untracked-files=all")):
            raise RuntimeError(f"{directory.name} already exists with different or modified contents")
    else:
        git("init", "--quiet", directory)
        git("-C", directory, "remote", "add", "origin", spec["repository"])
        git("-C", directory, "fetch", "--quiet", "--depth=1", "origin", spec["commit"])
        git("-C", directory, "checkout", "--quiet", "--detach", "FETCH_HEAD")
        if git("-C", directory, "rev-parse", "HEAD") != spec["commit"]:
            raise RuntimeError(f"Unexpected {name} commit")
    print(f"{name}: {spec['commit']}")


def main():
    lock = json.loads((PROJECT / "dependencies.lock.json").read_text())
    vendor = PROJECT / "vendor"
    if vendor.is_symlink():
        raise RuntimeError("vendor must be a local directory, not a symlink")
    vendor.mkdir(exist_ok=True)
    checkout("MacKernelSDK", lock["MacKernelSDK"], vendor / "MacKernelSDK")
    checkout("Lilu", lock["Lilu"], vendor / "Lilu-source")
    source = vendor / "Lilu-source"
    resources = vendor / "LiluResources"
    inputs = {}
    for directory in ("Headers", "Library"):
        for path in (source / "Lilu" / directory).rglob("*"):
            if path.is_file():
                inputs[path.relative_to(source / "Lilu")] = path
    for name in ("hde32.h", "hde64.h"):
        inputs[Path("Headers") / name] = source / "hde" / name
    if resources.exists():
        actual = {p.relative_to(resources) for p in resources.rglob("*") if p.is_file()}
        if (resources.is_symlink() or actual != set(inputs) or
                any((resources / key).is_symlink() or
                    (resources / key).read_bytes() != path.read_bytes()
                    for key, path in inputs.items())):
            raise RuntimeError("LiluResources already exists with different contents")
    else:
        resources.mkdir()
        for key, path in inputs.items():
            target = resources / key
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
    print("Build resources ready in vendor/MacKernelSDK and vendor/LiluResources")


if __name__ == "__main__":
    main()
