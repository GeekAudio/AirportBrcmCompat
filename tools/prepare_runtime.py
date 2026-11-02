#!/usr/bin/env python3
"""Fetch the small, hash-pinned runtime dependency for complete installation ZIPs."""
import hashlib
from pathlib import Path
import urllib.request
from verify_lilu_release_compatibility import RELEASES


def prepare(root=Path(__file__).resolve().parents[1]):
    spec=RELEASES['1.7.2']
    output=Path(root)/'build/research/Lilu-1.7.2-RELEASE.zip'
    if output.is_symlink():raise ValueError('Runtime archive must not be a symlink')
    if output.exists():
        data=output.read_bytes()
    else:
        with urllib.request.urlopen(spec['asset_url'],timeout=60) as response:
            data=response.read(spec['asset_size']+1)
    if len(data)!=spec['asset_size'] or hashlib.sha256(data).hexdigest()!=spec['asset_sha256']:
        raise ValueError('Runtime archive size or SHA-256 differs from the pinned release')
    output.parent.mkdir(parents=True,exist_ok=True)
    if not output.exists():
        with output.open('xb') as stream:stream.write(data)
    return output


if __name__=='__main__':
    print(prepare())
