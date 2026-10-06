from pathlib import Path
import sys

trace, mode, result, run = sys.argv[1:]
run = Path(run)
expected = []
if mode not in ("old-orbis", "pin-mismatch"):
    expected = ["build vera", "image vera normal"]
    if mode != "bad-image":
        for curve in ("bls12-381", "jubjub"):
            expected += ["build " + curve + " normal", "tree " + curve + " normal"]
            if mode == curve:
                break
            expected += ["image " + curve + " normal", "build " + curve + " diagnostic",
                         "tree " + curve + " diagnostic", "image " + curve + " diagnostic", "shared " + curve]
            assert (run / ("summary-" + curve + ".jsonl")).is_file()
            if mode == "shared-failure":
                break
            expected += ["retained-list " + curve,
                         "retained " + curve + " native_startup_registers_and_preserves_identity_on_restart"]
            if curve == "bls12-381":
                expected += ["retained " + curve + " native_defra_signing"]
actual = Path(trace).read_text().splitlines() if Path(trace).exists() else []
assert actual == expected, (actual, expected)
assert int(result) == (0 if mode == "none" else 73 if mode == "shared-failure" else 1), result
assert (run / "vera-Cargo.lock").is_file() and (run / "orbis-Cargo.lock").is_file()
