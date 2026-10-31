#!/usr/bin/env python3
"""Fetch four hash-pinned offline test inputs into build/; never install kexts."""
import argparse
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import stat
import urllib.request
import zipfile

ROOT=Path(__file__).resolve().parents[1]


def prepare(archive=None, *, root=ROOT, lock=None):
    root=Path(root).resolve()
    if lock is None:lock=json.loads((ROOT/'tests/fixtures.lock.json').read_text())
    limit=lock['max_download_bytes']
    if archive is None:
        with urllib.request.urlopen(lock['url'],timeout=60) as response:
            data=response.read(limit+1)
    else:
        with Path(archive).open('rb') as stream:data=stream.read(limit+1)
    if len(data)>limit or hashlib.sha256(data).hexdigest()!=lock['sha256']:
        raise ValueError('Test fixture archive hash or size mismatch')
    pending={}
    with zipfile.ZipFile(io.BytesIO(data)) as source:
        names=set()
        for member in source.infolist():
            name=member.filename;path=PurePosixPath(name)
            if (name in names or name not in lock['files'] or path.is_absolute() or
                    '..' in path.parts or '\\' in name or path.parts[0]!='build' or
                    member.is_dir() or member.file_size>limit or
                    stat.S_IFMT(member.external_attr>>16)==stat.S_IFLNK):
                raise ValueError('Unexpected test fixture archive member')
            names.add(name);payload=source.read(member)
            if hashlib.sha256(payload).hexdigest()!=lock['files'][name]:
                raise ValueError('Test fixture member hash mismatch')
            destination=root.joinpath(*path.parts)
            if any(parent.is_symlink() for parent in [destination,*destination.parents] if parent!=root.parent):
                raise ValueError('Test fixture destination contains a symlink')
            if destination.exists() and (not destination.is_file() or destination.read_bytes()!=payload):
                raise ValueError('Existing test fixture differs from the lock')
            pending[destination]=payload
        if names!=set(lock['files']):raise ValueError('Missing test fixture archive member')
    for destination,payload in pending.items():
        destination.parent.mkdir(parents=True,exist_ok=True)
        destination.write_bytes(payload)
    return len(pending)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive',type=Path,help='Use an already downloaded fixture archive')
    args=parser.parse_args()
    print('Verified offline test inputs:',prepare(args.archive))


if __name__=='__main__':main()
