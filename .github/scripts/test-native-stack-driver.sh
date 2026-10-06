#!/usr/bin/env bash
set -euo pipefail
scripts=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d "${TMPDIR:-/tmp}/native-stack-driver-tests.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
mkdir -p "$work/tools" "$work/repo/.github/scripts"
cp "$scripts/test-native-stack.sh" "$scripts/run-native-scenario.sh" \
    "$scripts/native-bind-race.py" "$work/repo/.github/scripts/"
cat > "$work/repo/backbone.toml" <<'PINS'
[components.verad]
ref = "1111111111111111111111111111111111111111"
[components.orbis-node]
ref = "2222222222222222222222222222222222222222"
[components.defra]
ref = "3333333333333333333333333333333333333333"
PINS

# No network or compiler is used. Test builds overwrite Cargo's production
# output to expose any driver that stages the executable too late or reuses it.
cat > "$work/tools/mock" <<'MOCK'
#!/usr/bin/env python3
import os
from pathlib import Path
import sys

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
if tool == "git":
    if args[:2] == ["init", "-q"]:
        Path(args[2]).mkdir(parents=True)
    else:
        assert args[0] == "-C", args
        repo = Path(args[1])
        command = args[2]
        if command == "fetch":
            (repo / "ref").write_text(args[-1])
        elif command == "checkout":
            (repo / "Cargo.toml").write_text("[workspace]\n")
            (repo / "Cargo.lock").write_text("# fixture lockfile\n")
            if repo.name == "orbis":
                manifest = repo / "bin/orbis-node/Cargo.toml"
                manifest.parent.mkdir(parents=True)
                manifest.write_text(
                    'vera = { git = "https://github.com/sourcenetwork/vera.rs", rev = "' + "1" * 40 + '" }\n'
                    'defra = { git = "https://github.com/sourcenetwork/defradb.rs", rev = "' + "3" * 40 + '" }\n'
                )
        elif command == "rev-parse":
            print((repo / "ref").read_text() if (repo / "ref").exists() else "4" * 40)
        else:
            raise AssertionError(args)
    sys.exit(0)
if tool == "rustc":
    print("rustc fixture")
    sys.exit(0)
assert tool == "cargo" and args.pop(0) == "+1.98.0", (tool, args)
command = args.pop(0)
for variable in os.environ:
    assert not variable.startswith("CARGO_PROFILE_"), variable
    assert not (variable.startswith("CARGO_TARGET_") and variable.endswith("_RUSTFLAGS")), variable
for variable in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                 "CARGO_INCREMENTAL", "CARGO_BUILD_INCREMENTAL", "CARGO_BUILD_TARGET",
                 "ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB", "ORBIS_LOCAL_STORAGE_KDF_T_COST"):
    assert variable not in os.environ, variable
assert os.environ["VERA_E2E_KEEP"] == "1"
assert "--manifest-path" in args
if command != "tree":
    assert "--release" in args
release = Path(os.environ["CARGO_TARGET_DIR"]) / "release"
release.mkdir(exist_ok=True)
if args[args.index("-p") + 1] == "verad":
    assert command == "build" and "--locked" in args
    (release / "verad").write_text("vera production\n")
    event = "build vera"
else:
    features = args[args.index("--features") + 1]
    curve = features.removeprefix("native,redb,iroh,")
    assert curve in ("bls12-381", "jubjub"), features
    assert "--no-default-features" in args and "--config" in args
    assert "acp-light-client.path=" in args[args.index("--config") + 1]
    event = command + " " + curve
    if command == "build":
        assert args[args.index("--bin") + 1] == "orbis-node"
        (release / "orbis-node").write_text(curve + " production\n")
    elif command == "tree":
        assert "--locked" in args and args[args.index("--edges") + 1] == "normal,build"
        assert args[args.index("--prefix") + 1] == "none"
        print("cosmrs v0.21.1" if os.environ["MOCK_FORBIDDEN"] == curve else "orbis-node v0.1.0")
    else:
        assert command == "test" and "--locked" in args
        assert args[args.index("--test") + 1] == "native_startup"
        staged = Path(os.environ["ORBIS_NODE_BINARY"])
        assert staged.parts[-3:] == ("bin", curve, "orbis-node"), staged
        assert staged.read_text() == curve + " production\n", staged
        assert Path(os.environ["VERAD_BINARY"]).read_text() == "vera production\n"
        (release / "orbis-node").write_text("test feature unification\n")
        if "--no-run" in args:
            event = "compile " + curve
        elif "--list" in args:
            event = "list " + curve
            print("native_startup_registers_and_preserves_identity_on_restart: test")
            if curve == "bls12-381":
                print("native_defra_signing: test")
            print("native_distributed_threshold_workflows: test")
            print("native_pet_threshold_workflows: test")
        else:
            scenario = args[args.index("--test") + 2]
            assert "--ignored" in args and "--exact" in args and "--test-threads=1" in args
            assert "--nocapture" in args and os.environ["NATIVE_STACK_CURVE"] == curve
            expected = curve + "-" + scenario
            assert Path(os.environ["VERA_E2E_DIR"]).parts[-3:] == (expected, "attempt-1", "clusters")
            retained = Path(os.environ["ORBIS_NATIVE_E2E_DIR"])
            assert retained.parts[-3:] == (expected, "attempt-1", "orbis-clusters")
            assert retained.is_dir()
            event = "run " + curve + " " + scenario
            print("test " + scenario + " ... ok")
with open(os.environ["MOCK_TRACE"], "a") as trace:
    trace.write(event + "\n")
MOCK
chmod +x "$work/tools/mock"
for tool in git cargo rustc; do ln -s mock "$work/tools/$tool"; done

for forbidden in none bls12-381 jubjub; do
    evidence_env="$work/$forbidden.env"
    trace="$work/$forbidden.trace"
    result=0
    PATH="$work/tools:$PATH" MOCK_TRACE="$trace" MOCK_FORBIDDEN="$forbidden" \
        GITHUB_ENV="$evidence_env" CARGO_TARGET_DIR="$work/target-$forbidden" \
        CARGO_PROFILE_RELEASE_LTO=false CARGO_TARGET_AARCH64_APPLE_DARWIN_RUSTFLAGS=fixture \
        RUSTFLAGS=fixture CARGO_ENCODED_RUSTFLAGS=fixture CARGO_BUILD_RUSTFLAGS=fixture \
        CARGO_INCREMENTAL=1 CARGO_BUILD_INCREMENTAL=1 CARGO_BUILD_TARGET=fixture \
        ORBIS_LOCAL_STORAGE_KDF_M_COST_KIB=32 ORBIS_LOCAL_STORAGE_KDF_T_COST=1 \
        bash "$work/repo/.github/scripts/test-native-stack.sh" > "$work/$forbidden.log" 2>&1 || result=$?
    run=$(sed -n 's/^NATIVE_STACK_EVIDENCE=//p' "$evidence_env")
    [[ -f $run/vera-Cargo.lock && -f $run/orbis-Cargo.lock ]]
    python3 - "$trace" "$forbidden" "$result" "$run" <<'CHECK'
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
CHECK
    printf 'PASS native-stack-driver forbidden=%s\n' "$forbidden"
done
