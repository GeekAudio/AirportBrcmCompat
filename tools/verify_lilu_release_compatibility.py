#!/usr/bin/env python3
"""Opt-in Lilu 1.7.1/1.7.2 header and release-binary compatibility check.

This downloads two small official release assets and shallow-fetches only the
headers needed for a build. It never installs or loads a kext. Evidence is
written only to the ignored build/ directory.
"""

import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile


PROJECT = Path(__file__).resolve().parents[1]
RUNTIME_MINIMUM = '1.7.1'
RELEASES = {
    '1.7.1': {
        'commit': 'dc01cb583295ceded4f42a6310a15e3abac1c025',
        'asset_url': 'https://github.com/acidanthera/Lilu/releases/download/1.7.1/Lilu-1.7.1-RELEASE.zip',
        'asset_sha256': 'a2c8cf8db59bcbb725b24782b7b75a5f3779fc4eb514d5cec21803b7e14902c3',
        'asset_size': 782537,
    },
    '1.7.2': {
        'commit': 'e4748cc081bf060302c7d3c44a643ce1d11b7e1d',
        'asset_url': 'https://github.com/acidanthera/Lilu/releases/download/1.7.2/Lilu-1.7.2-RELEASE.zip',
        'asset_sha256': '53967d7dcfaab01023a33df2e969a89522f13d6654a6a56ac4711b62dabf3ab8',
        'asset_size': 781360,
    },
}

REQUIRED_EXPORTS = {
    '__ZN13KernelPatcher10clearErrorEv',
    '__ZN13KernelPatcher11solveSymbolEmPKc',
    '__ZN13KernelPatcher13routeMultipleEmPNS_12RouteRequestEmymbb',
    '__ZN13KernelPatcher17routeMultipleLongEmPNS_12RouteRequestEmymbb',
    '__ZN13KernelPatcher18routeMultipleShortEmPNS_12RouteRequestEmymbb',
    '__ZN13KernelPatcher8getErrorEv',
    '__ZN7LiluAPI10onKextLoadEPN13KernelPatcher8KextInfoEmPFvPvRS0_mymES3_',
    '__ZN7LiluAPI10shouldLoadEPKcmjPS1_mS2_mS2_m13KernelVersionS3_Rb',
    '__ZN7LiluAPI13onPatcherLoadEPFvPvR13KernelPatcherES0_',
    '__ZN7LiluAPI13releaseAccessEv',
    '__ZN7LiluAPI13requestAccessEmb',
}

PLUGIN_ABI_PROBE = r'''#include <stddef.h>
#include <Headers/kern_api.hpp>
#include <Headers/plugin_start.hpp>
static_assert(sizeof(KernelPatcher::KextInfo) == 40, "KextInfo ABI changed");
static_assert(sizeof(PluginConfiguration) == 88, "PluginConfiguration ABI changed");
static_assert(offsetof(PluginConfiguration, minKernel) == 72, "minKernel offset changed");
static_assert(offsetof(PluginConfiguration, maxKernel) == 76, "maxKernel offset changed");
static_assert(offsetof(PluginConfiguration, pluginStart) == 80, "pluginStart offset changed");
'''


def run(arguments, *, cwd=None, timeout=600, input_text=None):
    result = subprocess.run([str(item) for item in arguments], cwd=cwd,
                            input=input_text, capture_output=True, text=True,
                            timeout=timeout)
    if result.returncode:
        details = result.stderr.strip() or result.stdout.strip()
        raise RuntimeError(f"Command failed: {' '.join(map(str, arguments))}\n{details}")
    return result.stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def directory_sha256(root):
    digest = hashlib.sha256()
    files = sorted(path for path in root.rglob('*') if path.is_file())
    for path in files:
        relative = path.relative_to(root).as_posix().encode()
        digest.update(len(relative).to_bytes(4, 'little'))
        digest.update(relative)
        data = path.read_bytes()
        digest.update(len(data).to_bytes(8, 'little'))
        digest.update(data)
    return digest.hexdigest(), len(files)


def extract_lilu_resources(source, destination):
    inputs = {}
    for directory in ('Headers', 'Library'):
        base = source / 'Lilu' / directory
        for path in base.rglob('*'):
            if path.is_file():
                resolved = path.resolve(strict=True)
                try:
                    resolved.relative_to(source.resolve())
                except ValueError as error:
                    raise RuntimeError(f'Lilu source symlink escapes checkout: {path}') from error
                inputs[path.relative_to(source / 'Lilu')] = path
    for name in ('hde32.h', 'hde64.h'):
        path = source / 'hde' / name
        if not path.is_file() or path.is_symlink():
            raise RuntimeError(f'Missing official Lilu dependency header: {path}')
        inputs[Path('Headers') / name] = path
    if not inputs:
        raise RuntimeError('No Lilu headers were found')
    destination.mkdir(parents=True)
    for relative, path in inputs.items():
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(path, target)
    return directory_sha256(destination)


def fetch_release_source(version, temporary):
    spec = RELEASES[version]
    source = temporary / f'Lilu-source-{version}'
    source.mkdir()
    run(['git', 'init', '--quiet', source])
    run(['git', '-C', source, 'remote', 'add', 'origin', 'https://github.com/acidanthera/Lilu.git'])
    run(['git', '-C', source, 'sparse-checkout', 'init', '--cone'])
    run(['git', '-C', source, 'sparse-checkout', 'set', 'Lilu/Headers', 'Lilu/Library', 'hde'])
    run(['git', '-C', source, 'fetch', '--quiet', '--depth=1', '--filter=blob:none',
         'origin', spec['commit']])
    run(['git', '-C', source, 'checkout', '--quiet', '--detach', 'FETCH_HEAD'])
    actual = run(['git', '-C', source, 'rev-parse', 'HEAD']).strip()
    if actual != spec['commit']:
        raise RuntimeError(f'Unexpected Lilu {version} source revision: {actual}')
    return source


def download_release_binary(version, temporary):
    spec = RELEASES[version]
    request = urllib.request.Request(spec['asset_url'], headers={
        'User-Agent': 'AirportBrcmCompat-Lilu-compatibility-check/1.0',
    })
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(2_000_001)
    if len(data) != spec['asset_size']:
        raise RuntimeError(f'Unexpected Lilu {version} release asset size: {len(data)}')
    digest = sha256(data)
    if digest != spec['asset_sha256']:
        raise RuntimeError(f'Unexpected Lilu {version} release asset SHA-256: {digest}')
    archive = temporary / f'Lilu-{version}-RELEASE.zip'
    archive.write_bytes(data)
    with zipfile.ZipFile(archive) as bundle:
        name = 'Lilu.kext/Contents/MacOS/Lilu'
        if name not in bundle.namelist():
            raise RuntimeError(f'Lilu {version} release archive has no {name}')
        binary = temporary / f'Lilu-{version}'
        binary.write_bytes(bundle.read(name))
    return binary, digest


def normalize_symbol(symbol):
    return symbol.strip().lstrip('_')


def exported_symbols(nm, binary):
    output = run([nm, '-gjU', binary])
    return {normalize_symbol(line) for line in output.splitlines() if line.strip()}


def verify_release_exports(version, nm, temporary):
    binary, asset_digest = download_release_binary(version, temporary)
    exports = exported_symbols(nm, binary)
    required = {normalize_symbol(item) for item in REQUIRED_EXPORTS}
    missing = sorted(required - exports)
    if missing:
        raise RuntimeError(f'Lilu {version} release is missing required exported APIs: {missing}')
    return asset_digest, len(exports), exports


def verify_plugin_layout(compiler, sdk, resources, temporary, version):
    source = temporary / f'plugin-abi-{version}.cpp'
    source.write_text(PLUGIN_ABI_PROBE)
    run([
        compiler, '-std=c++14', '-fapple-kext', '-fno-exceptions', '-fno-rtti',
        '-nostdinc++', '-DKERNEL=1', '-DKERNEL_PRIVATE=1',
        '-DLILU_CUSTOM_KMOD_INIT=1', '-DLILU_CUSTOM_IOKIT_INIT=1',
        '-mmacosx-version-min=10.15', '-isystem', sdk / 'Headers',
        '-I', resources, '-fsyntax-only', source,
    ])
    return {
        'kext_info_size': 40,
        'plugin_configuration_size': 88,
        'plugin_configuration_offsets': {'minKernel': 72, 'maxKernel': 76, 'pluginStart': 80},
    }


def build_project(version, resources, temporary, release_exports):
    output = temporary / f'AirportBrcmCompat-Lilu-{version}.zip'
    text = run([
        sys.executable, PROJECT / 'tools/build_unified_kernel.py',
        '--automatic-compatibility', '--output', output,
        '--lilu-resources', resources,
    ], cwd=PROJECT)
    summary = json.loads(text.strip().splitlines()[-1])
    with zipfile.ZipFile(output) as package:
        manifest = json.loads(package.read('build-manifest.json'))
        info_path = 'AirportBrcmCompat.kext/Contents/Info.plist'
        if info_path not in package.namelist():
            raise RuntimeError(f'Lilu {version} build omitted the product Info.plist')
        import plistlib
        info = plistlib.loads(package.read(info_path))
    minimum = info.get('OSBundleLibraries', {}).get('as.vit9696.Lilu')
    if minimum != RUNTIME_MINIMUM:
        raise RuntimeError(f'Build for Lilu {version} has unexpected runtime minimum: {minimum}')
    imports = {normalize_symbol(line.split()[-1]) for line in manifest.get('nm_undefined', [])
               if line.split()}
    lilu_imports = sorted(symbol for symbol in imports
                          if symbol.startswith(('ZN7LiluAPI', 'ZN13KernelPatcher', 'ZN8MachInfo')))
    if any(symbol.startswith('ZN8MachInfo') for symbol in lilu_imports):
        raise RuntimeError('Built product still imports the Lilu MachInfo object API')
    missing = sorted(set(lilu_imports) - release_exports)
    if missing:
        raise RuntimeError(f'Lilu {version} release does not export product imports: {missing}')
    return {
        'package_sha256': summary['sha256'],
        'runtime_lilu_minimum': minimum,
        'lilu_imports': lilu_imports,
        'unresolved_lilu_import_count': len(lilu_imports),
    }


def verify_ignored_output(path):
    if path.is_symlink():
        raise RuntimeError('build evidence directory must not be a symlink')
    result = subprocess.run(['git', '-C', str(PROJECT), 'check-ignore', '-q', str(path)],
                            capture_output=True)
    if result.returncode:
        raise RuntimeError(f'Evidence path is not git-ignored: {path}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args(argv)
    if sys.platform != 'darwin':
        raise RuntimeError('Release header compilation requires macOS and Xcode Command Line Tools')
    build_source = PROJECT / 'vendor/Lilu-source'
    build_resources = PROJECT / 'vendor/LiluResources'
    sdk = PROJECT / 'vendor/MacKernelSDK'
    lock = json.loads((PROJECT / 'dependencies.lock.json').read_text())
    pinned = lock['Lilu']
    if pinned.get('version') != '1.7.2' or pinned.get('commit') != RELEASES['1.7.2']['commit']:
        raise RuntimeError('Refresh dependencies.lock.json to the official Lilu 1.7.2 release pin')
    if run(['git', '-C', build_source, 'rev-parse', 'HEAD']).strip() != pinned['commit']:
        raise RuntimeError('Run tools/prepare_dependencies.py to refresh the pinned Lilu checkout')
    if not build_resources.is_dir() or not (sdk / 'Headers').is_dir():
        raise RuntimeError('Run tools/prepare_dependencies.py before the release compatibility check')
    compiler = run(['xcrun', '--find', 'clang++']).strip()
    nm = run(['xcrun', '--find', 'nm']).strip()
    evidence = {
        'schema': 1,
        'runtime_minimum': RUNTIME_MINIMUM,
        'build_pin': {'version': pinned['version'], 'commit': pinned['commit']},
        'checks': [],
    }

    with tempfile.TemporaryDirectory(prefix='airport-lilu-api-') as directory:
        temporary = Path(directory)
        for version in ('1.7.1', '1.7.2'):
            if version == '1.7.2':
                source = build_source
            else:
                source = fetch_release_source(version, temporary)
            resources = temporary / f'LiluResources-{version}'
            headers_digest, header_count = extract_lilu_resources(source, resources)
            layout = verify_plugin_layout(compiler, sdk, resources, temporary, version)
            asset_digest, export_count, exports = verify_release_exports(version, nm, temporary)
            build = build_project(version, resources, temporary, exports)
            evidence['checks'].append({
                'version': version,
                'source_commit': RELEASES[version]['commit'],
                'header_resource_sha256': headers_digest,
                'header_resource_files': header_count,
                'release_asset_sha256': asset_digest,
                'release_exported_symbol_count': export_count,
                'plugin_layout': layout,
                'build': build,
            })

    destination = PROJECT / 'build/lilu-api-compatibility.json'
    verify_ignored_output(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(evidence, indent=2) + '\n')
    print(json.dumps({'evidence': str(destination), 'versions': [c['version'] for c in evidence['checks']],
                      'runtime_minimum': RUNTIME_MINIMUM, 'build_pin': pinned['version']}))


if __name__ == '__main__':
    try:
        main()
    except (OSError, RuntimeError, subprocess.SubprocessError, zipfile.BadZipFile) as error:
        print(f'verify_lilu_release_compatibility: {error}', file=sys.stderr)
        raise SystemExit(1)
