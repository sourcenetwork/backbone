#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

tool, args = Path(sys.argv[0]).name, sys.argv[1:]
fault = os.environ['MOCK_FORBIDDEN']


def record(event):
    with open(os.environ['MOCK_TRACE'], 'a') as trace:
        trace.write(event + '\n')


if tool == 'git':
    if args[:2] == ['init', '-q']:
        Path(args[2]).mkdir(parents=True)
    else:
        assert args[0] == '-C', args
        repo, command = Path(args[1]), args[2]
        if command == 'fetch':
            (repo / 'fetch_ref').write_text(args[-1])
        elif command == 'checkout':
            (repo / 'head').write_text((repo / 'fetch_ref').read_text())
            (repo / 'Cargo.toml').write_text('[workspace]\n')
            (repo / 'Cargo.lock').write_text('# fixture lockfile\n')
            if repo.name == 'orbis':
                manifest = repo / 'bin/orbis-node/Cargo.toml'
                manifest.parent.mkdir(parents=True)
                manifest.write_text(
                    'vera = { git = "https://github.com/sourcenetwork/vera.rs", rev = "' + '1' * 40 + '" }\n'
                    'defra = { git = "https://github.com/sourcenetwork/defradb.rs", rev = "' + '3' * 40 + '" }\n'
                    'acp-light-client = { git = "https://github.com/sourcenetwork/backbone.git", rev = "' + '6' * 40 + '" }\n')
                guard = repo / 'scripts/qualify-native-restart.py'
                guard.parent.mkdir(parents=True)
                guard.write_text('def verify_fixture_changes(paths):\n'
                                 '    if paths: raise ValueError("runtime source differs")\n')
        elif command == 'rev-parse':
            if args[-1].endswith('^{tree}'):
                wrong = fault == 'source' and args[-1].startswith('5' * 40)
                print(('8' if wrong else '7') * 40)
            else:
                print((repo / 'head').read_text() if (repo / 'head').exists() else '4' * 40)
        elif command == 'status':
            pass
        elif command == 'diff':
            if '--quiet' in args and fault == 'proof':
                sys.exit(1)
            if '--name-only' in args and fault == 'fixture':
                print('bin/orbis-node/src/node.rs')
        else:
            raise AssertionError(args)
    sys.exit(0)
if tool == 'rustc':
    print('rustc fixture')
    sys.exit(0)
for variable in os.environ:
    assert not variable.startswith('CARGO_PROFILE_'), variable
    assert not (variable.startswith('CARGO_TARGET_') and variable.endswith('_RUSTFLAGS')), variable
for variable in ('RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'CARGO_BUILD_RUSTFLAGS',
                 'CARGO_INCREMENTAL', 'CARGO_BUILD_INCREMENTAL', 'CARGO_BUILD_TARGET',
                 'ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB', 'ORBIS_LOCAL_STORAGE_KDF_T_COST'):
    assert variable not in os.environ, variable
assert os.environ['VERA_E2E_KEEP'] == '1'
if tool == 'docker':
    image = args[-1]
    role = {'8': 'vera', '9': 'bls12-381', 'a': 'jubjub'}[image[-1]]
    if args[0] == 'pull':
        record('pull ' + role)
    else:
        assert args[:2] == ['image', 'inspect'], args
        labels = {'org.opencontainers.image.revision': ('1' if role == 'vera' else '5') * 40}
        if role != 'vera':
            labels.update({'io.sourcenetwork.orbis.backend': 'native',
                           'io.sourcenetwork.orbis.curve': role,
                           'io.sourcenetwork.orbis.integration-features':
                               'true' if fault == 'image' and role == 'bls12-381' else 'false'})
        print(json.dumps([{'Id': 'sha256:' + {'vera': 'b', 'bls12-381': 'c', 'jubjub': 'd'}[role] * 64,
                           'RepoDigests': [image], 'Os': 'linux', 'Architecture': 'amd64',
                           'Config': {'Labels': labels,
                                      'Entrypoint': ['verad' if role == 'vera' else 'orbis-node']}}]))
        record('inspect ' + role)
    sys.exit(0)
assert tool == 'cargo' and args.pop(0) == '+1.98.0', (tool, args)
command = args.pop(0)
assert '--manifest-path' in args
assert args[args.index('-p') + 1] == 'orbis-node'
features = args[args.index('--features') + 1]
curve = features.removeprefix('native,redb,iroh,')
assert curve in ('bls12-381', 'jubjub'), features
assert '--no-default-features' in args and '--config' in args
assert 'acp-light-client.path=' in args[args.index('--config') + 1]
assert os.environ['ORBIS_NATIVE_IMAGE'].endswith(('9' if curve == 'bls12-381' else 'a') * 64)
assert os.environ['ORBIS_NATIVE_VERA_IMAGE'].endswith('8' * 64)
event = command + ' ' + curve
if command == 'tree':
    assert args[args.index('--edges') + 1] == 'normal,build'
    assert args[args.index('--prefix') + 1] == 'none'
    print('cosmrs v0.21.1' if fault == curve else 'orbis-node v0.1.0')
else:
    assert command == 'test' and '--locked' in args and '--release' in args
    assert args[args.index('--test') + 1] == 'native_startup'
    assert 'ORBIS_NODE_BINARY' not in os.environ and 'VERAD_BINARY' not in os.environ
    if '--no-run' in args:
        event = 'compile ' + curve
    elif '--list' in args:
        event = 'list ' + curve
        print('native_startup_registers_and_preserves_identity_on_restart: test')
        if curve == 'bls12-381':
            print('native_defra_signing: test')
        print('native_distributed_threshold_workflows: test')
        print('native_pet_threshold_workflows: test')
    else:
        scenario = args[args.index('--test') + 2]
        assert '--ignored' in args and '--exact' in args and '--test-threads=1' in args
        assert '--nocapture' in args and os.environ['NATIVE_STACK_CURVE'] == curve
        expected = curve + '-' + scenario
        assert Path(os.environ['VERA_E2E_DIR']).parts[-3:] == (expected, 'attempt-1', 'clusters')
        retained = Path(os.environ['ORBIS_NATIVE_E2E_DIR'])
        assert retained.parts[-3:] == (expected, 'attempt-1', 'orbis-clusters')
        assert retained.is_dir()
        event = 'run ' + curve + ' ' + scenario
        print('test ' + scenario + ' ... ok')
record(event)
