from pathlib import Path
import sys

trace, forbidden, result, run = sys.argv[1:]
run = Path(run)
expected = ["build vera"]
for curve in ("bls12-381", "jubjub"):
    expected += ["build " + curve, "tree " + curve]
    assert (run / ("build-orbis-" + curve + ".log")).exists()
    assert (run / ("native-dependencies-" + curve + ".log")).exists()
    assert (run / ("provenance-" + curve + ".log")).exists()
    if forbidden == curve:
        break
    expected += ["compile " + curve, "list " + curve]
    scenarios = ["native_startup_registers_and_preserves_identity_on_restart"]
    if curve == "bls12-381":
        scenarios += ["native_defra_signing"]
    scenarios += ["native_distributed_threshold_workflows", "native_pet_threshold_workflows"]
    for scenario in scenarios:
        expected += ["run " + curve + " " + scenario]
        attempt = run / "scenarios" / (curve + "-" + scenario) / "attempt-1"
        assert (attempt / "command.log").is_file()
        assert (attempt / "exit-code").read_text() == "0\n"
    assert (run / ("build-tests-" + curve + ".log")).exists()
    assert (run / ("scenarios-" + curve + ".log")).exists()
assert Path(trace).read_text().splitlines() == expected, Path(trace).read_text()
assert int(result) == (0 if forbidden == "none" else 1), result
assert not (run / "scenarios/jubjub-native_defra_signing").exists()
