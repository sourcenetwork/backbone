from pathlib import Path
import sys

trace, forbidden, result, run = sys.argv[1:]
run = Path(run)
expected = ["build vera", "image vera"]
assert (run / "vera-image-id.txt").read_text().startswith("sha256:")
for curve in ("bls12-381", "jubjub"):
    expected += ["build " + curve, "tree " + curve]
    assert (run / ("build-orbis-" + curve + ".log")).exists()
    assert (run / ("native-dependencies-" + curve + ".log")).exists()
    assert (run / ("provenance-" + curve + ".log")).exists()
    if forbidden == curve:
        break
    expected += ["image " + curve, "compile " + curve, "list " + curve]
    assert (run / ("orbis-image-id-" + curve + ".txt")).read_text().startswith("sha256:")
    scenarios = ['tests::e2e::restart_scenario::test_restarted_member_keeps_identity_and_polynomial', 'tests::e2e::member_replacement::test_spare_member_replaces_original', 'tests::e2e::integration::test_cli_calls_dkg_for_pet_ring']
    for scenario in scenarios:
        expected += ["run " + curve + " " + scenario]
        attempt = run / "scenarios" / (curve + "-" + scenario.replace("::", "--")) / "attempt-1"
        assert (attempt / "command.log").is_file()
        assert (attempt / "exit-code").read_text() == "0\n"
    assert (run / ("build-tests-" + curve + ".log")).exists()
    assert (run / ("scenarios-" + curve + ".log")).exists()
assert Path(trace).read_text().splitlines() == expected, Path(trace).read_text()
assert int(result) == (0 if forbidden == "none" else 1), result
