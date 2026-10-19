#!/usr/bin/env python3
"""Verify and record the immutable normal images used by native stack tests.

Expected digests, image IDs and build revisions come from independent CI evidence.
Source checks bind the CI build tree to the selected runtime; Orbis fixture-only
changes must pass its existing qualification guard.
"""
import argparse
import json
from pathlib import Path
import re
import runpy
import subprocess
import sys

REPOSITORIES = {
    'orbis': 'ghcr.io/sourcenetwork/orbis-rs/node-integration',
    'vera': 'ghcr.io/sourcenetwork/orbis-rs/vera-native',
}


class QualificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise QualificationError(message)


def verify(info, image, image_id, source, role, curve=None):
    require(isinstance(role, str) and role in REPOSITORIES, 'unknown native image role')
    repository = REPOSITORIES[role]
    require(isinstance(image, str) and re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', image),
            'native image must use the expected repository and an immutable digest')
    require(isinstance(image_id, str) and re.fullmatch(r'sha256:[0-9a-f]{64}', image_id), 'invalid expected image ID')
    require(isinstance(source, str) and re.fullmatch(r'[0-9a-f]{40}', source), 'invalid expected image source')
    require(isinstance(info, dict), 'invalid native image metadata')
    require(info.get('Id') == image_id, 'native image ID differs from the qualified build')
    digests = info.get('RepoDigests')
    require(isinstance(digests, list) and image in digests, 'native repository digest mismatch')
    require(info.get('Os') == 'linux' and info.get('Architecture') == 'amd64',
            'native qualification requires Linux amd64 images')
    config = info.get('Config')
    require(isinstance(config, dict), 'missing native image configuration')
    labels = config.get('Labels')
    require(isinstance(labels, dict), 'missing native image source labels')
    require(labels.get('org.opencontainers.image.revision') == source,
            'native image source differs from the qualified build')
    expected = {'org.opencontainers.image.revision': source}
    if role == 'orbis':
        require(curve in ('bls12-381', 'jubjub'), 'invalid native image curve')
        expected.update({
            'io.sourcenetwork.orbis.backend': 'native',
            'io.sourcenetwork.orbis.curve': curve,
            'io.sourcenetwork.orbis.integration-features': 'false',
        })
        require(all(labels.get(key) == value for key, value in expected.items()),
                'native image backend, curve or integration mode mismatch')
        require(labels.get('io.sourcenetwork.orbis.unsafe-testing') in (None, 'false'),
                'diagnostic image cannot qualify the normal native runtime')
    else:
        require(curve is None, 'Vera image cannot select an Orbis curve')
    require(config.get('Entrypoint') == ['orbis-node' if role == 'orbis' else 'verad'],
            'native image entrypoint mismatch')
    return {'image': image, 'image_id': image_id, 'source': source, 'role': role,
            'curve': curve, 'os': info['Os'], 'architecture': info['Architecture'],
            'labels': expected}



def verify_source(checkout, source, runtime_source=None):
    require(re.fullmatch(r'[0-9a-f]{40}', source), 'invalid image build revision')
    runtime = runtime_source or source
    require(re.fullmatch(r'[0-9a-f]{40}', runtime), 'invalid runtime revision')

    def git(*args):
        return subprocess.check_output(['git', '-C', str(checkout), *args],
                                       text=True, timeout=30).strip()

    require(not git('status', '--porcelain', '--untracked-files=no'),
            'native image checkout has tracked changes')
    head = git('rev-parse', 'HEAD')
    image_tree = git('rev-parse', source + '^{tree}')
    require(image_tree == git('rev-parse', runtime + '^{tree}'),
            'image build tree differs from the selected runtime')
    if runtime_source is None:
        require(head == source, 'Vera image source differs from the selected runtime')
    else:
        changed = git('diff', '--no-ext-diff', '--no-textconv', '--no-renames',
                      '--name-only', runtime, head, '--').splitlines()
        guard = runpy.run_path(str(checkout / 'scripts/qualify-native-restart.py'))
        guard['verify_fixture_changes'](changed)
    return {'fixture': head, 'runtime': runtime, 'build': source, 'runtime_tree': image_tree}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--role', required=True, choices=tuple(REPOSITORIES))
    parser.add_argument('--curve', choices=('bls12-381', 'jubjub'))
    parser.add_argument('--image', required=True)
    parser.add_argument('--image-id', required=True)
    parser.add_argument('--source', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--checkout', required=True, type=Path)
    parser.add_argument('--runtime-source')
    args = parser.parse_args()
    repository = REPOSITORIES[args.role]
    require(re.fullmatch(re.escape(repository) + r'@sha256:[0-9a-f]{64}', args.image),
            'native image must use the expected repository and an immutable digest')
    sources = verify_source(args.checkout, args.source, args.runtime_source)
    subprocess.run(['docker', 'pull', args.image], check=True, timeout=600)
    inspected = json.loads(subprocess.check_output(
        ['docker', 'image', 'inspect', args.image], timeout=30))
    require(isinstance(inspected, list) and len(inspected) == 1,
            'expected exactly one native image')
    result = verify(inspected[0], args.image, args.image_id, args.source, args.role, args.curve)
    result['sources'] = sources
    args.output.write_text(json.dumps(result, indent=2) + '\n')


if __name__ == '__main__':
    try:
        main()
    except (QualificationError, subprocess.SubprocessError, OSError, ValueError) as error:
        message = str(error) if isinstance(error, QualificationError) else 'native image inspection failed'
        print(message, file=sys.stderr)
        sys.exit(1)
