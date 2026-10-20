import json
from pathlib import Path
import sys

trace, forbidden, result, run = sys.argv[1:]
run = Path(run)
expected = []
if forbidden != 'proof':
    expected += ['pull vera', 'inspect vera']
    if forbidden not in ('source', 'fixture'):
        expected += ['pull bls12-381', 'inspect bls12-381']
        if forbidden != 'image':
            expected += ['pull jubjub', 'inspect jubjub']
            for role in ('vera', 'bls12-381', 'jubjub'):
                image = json.loads((run / ('image-' + role + '.json')).read_text())
                assert image['image'].startswith('ghcr.io/sourcenetwork/orbis-rs/')
                assert image['sources']['build'] == ('1' if role == 'vera' else '5') * 40
            for curve in ('bls12-381', 'jubjub'):
                expected += ['tree ' + curve]
                assert (run / ('native-dependencies-' + curve + '.log')).exists()
                if forbidden == curve:
                    break
                expected += ['compile ' + curve, 'list ' + curve]
                scenarios = ['native_startup_registers_and_preserves_identity_on_restart']
                if curve == 'bls12-381':
                    scenarios += ['native_defra_signing']
                scenarios += ['native_distributed_threshold_workflows', 'native_pet_threshold_workflows']
                for scenario in scenarios:
                    expected += ['run ' + curve + ' ' + scenario]
                    attempt = run / 'scenarios' / (curve + '-' + scenario) / 'attempt-1'
                    assert (attempt / 'command.log').is_file()
                    assert (attempt / 'exit-code').read_text() == '0\n'
                assert (run / ('build-tests-' + curve + '.log')).exists()
actual = Path(trace).read_text().splitlines() if Path(trace).exists() else []
assert actual == expected, actual
assert int(result) == (0 if forbidden == 'none' else 1), result
assert not (run / 'scenarios/jubjub-native_defra_signing').exists()
