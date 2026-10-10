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
                with manifest.open("a") as output:
                    output.write('acp-light-client = { git = "https://github.com/sourcenetwork/backbone.git", rev = "' + "4" * 40 + '" }\n')
                (repo / "docker").mkdir()
                (repo / "docker/NATIVE_VERA_REF").write_text("1" * 40 + "\n")
        elif command in ("cat-file", "diff"):
            if os.environ.get("MOCK_SDK_MISMATCH") and command == "diff" and "--name-only" not in args:
                sys.exit(1)
            if command == "diff" and "--name-only" in args:
                print("bin/orbis-node/src/runtime/mod.rs" if os.environ.get("MOCK_RUNTIME_CHANGE")
                      else "docker/docker-compose-native-integration-test.yml")
        elif command == "rev-parse":
            if os.environ.get("MOCK_CLIENT_TREE_MISMATCH") and args[-1] == "HEAD:crates/acp-light-client":
                print("5" * 40)
            else:
                print((repo / "ref").read_text() if (repo / "ref").exists() else "4" * 40)
        else:
            raise AssertionError(args)
    sys.exit(0)
if tool == "rustc":
    print("rustc fixture")
    sys.exit(0)
if tool == "docker":
    image = args[-1]
    curve = "jubjub" if image.endswith("jubjub") else "bls12-381"
    if args[0] == "pull":
        event = "pull vera" if "/vera-native:" in image else "pull " + curve
        with open(os.environ["MOCK_TRACE"], "a") as trace:
            trace.write(event + "\n")
    else:
        assert args[:2] == ["image", "inspect"], args
        field = args[args.index("--format") + 1]
        if field == "{{.Id}}":
            print("sha256:" + ("1" * 64 if "/vera-native:" in image else ("2" if curve == "bls12-381" else "3") * 64))
        elif "org.opencontainers.image.revision" in field:
            print(("1" if "/vera-native:" in image else "2") * 40)
        elif "orbis.backend" in field:
            print("native")
        elif "orbis.curve" in field:
            print(curve)
        elif "orbis.integration-features" in field:
            print("true" if os.environ.get("MOCK_UNSAFE_IMAGE") else "false")
        else:
            raise AssertionError(args)
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
    assert "--no-default-features" in args and "--config" not in args
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
        assert "ORBIS_NODE_BINARY" not in os.environ and "VERAD_BINARY" not in os.environ
        assert os.environ["ORBIS_NATIVE_VERA_IMAGE"] == "sha256:" + "1" * 64
        assert os.environ["ORBIS_NATIVE_IMAGE"] == "sha256:" + ("2" if curve == "bls12-381" else "3") * 64
        if "--no-run" in args:
            event = "compile " + curve
        elif "--list" in args:
            event = ("list-ignored " if "--ignored" in args else "list ") + curve
            if "--ignored" not in args:
                print("native_startup_registers_and_preserves_identity_on_restart: test")
                if curve == "bls12-381":
                    print("native_defra_signing: test")
                print("native_distributed_threshold_workflows: test")
                print("native_pet_threshold_workflows: test")
                print("native_pet_member_replacement: test")
                print("native_pet_scheduled_refresh_after_restart: test")
            elif os.environ.get("MOCK_IGNORED_SCENARIO"):
                print("native_startup_registers_and_preserves_identity_on_restart: test")
        else:
            scenario = args[args.index("--test") + 2]
            assert "--ignored" not in args and "--exact" in args and "--test-threads=1" in args
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
