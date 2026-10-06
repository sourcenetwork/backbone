#!/usr/bin/env python3
"""Fake external tools: assert staging, pin checks and image/test isolation."""
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile

def record(event):
    with open(os.environ["MOCK_TRACE"], "a") as trace:
        trace.write(event + "\n")

def sanitized():
    for name in os.environ:
        assert not name.startswith(("CARGO_PROFILE_", "ORBIS_LOCAL_STORAGE_KDF_", "CARGO_BUILD_RUSTC")), name
        assert not (name.startswith("CARGO_TARGET_") and name.endswith("_RUSTFLAGS")), name
    for name in ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
                 "CARGO_INCREMENTAL", "CARGO_BUILD_INCREMENTAL", "CARGO_BUILD_TARGET",
                 "RUSTC", "RUSTDOC", "RUSTUP_TOOLCHAIN", "VERA_E2E_DEADLINE_SCALE"):
        assert name not in os.environ, name
    assert os.environ["VERA_E2E_KEEP"] == "1"
    assert os.environ["CARGO_BUILD_JOBS"] == "2"

tool = Path(sys.argv[0]).name
args = sys.argv[1:]
mode = os.environ["MOCK_MODE"]
state = Path(os.environ["MOCK_DOCKER_STATE"])
if tool == "git":
    if args[:2] == ["init", "-q"]:
        Path(args[2]).mkdir(parents=True)
    else:
        assert args[0] == "-C", args
        repo, command = Path(args[1]), args[2]
        if command == "fetch":
            (repo / "ref").write_text(args[-1])
        elif command == "checkout":
            (repo / "Cargo.toml").write_text("[workspace]\n")
            (repo / "Cargo.lock").write_text("# fixture lockfile\n")
            if repo.name == "orbis":
                manifest = repo / "bin/orbis-node/Cargo.toml"
                manifest.parent.mkdir(parents=True)
                manifest.write_text('defra = { git = "https://github.com/sourcenetwork/defradb.rs", rev = "'
                                    + "3" * 40 + '" }\n')
                scripts = repo / "scripts"
                scripts.mkdir()
                revision = "9" * 40 if mode == "pin-mismatch" else "1" * 40
                (scripts / "native-vera-ref.py").write_text('print("' + revision + '")\n')
                (scripts / "native_lifecycle_summary.py").touch()
                if mode != "old-orbis":
                    (scripts / "test-native-integration.sh").write_text(
                        '#!/usr/bin/env bash\nset -euo pipefail\nexec native-shared-suite "$1"\n')
        elif command == "rev-parse":
            print((repo / "ref").read_text() if (repo / "ref").exists() else "4" * 40)
        elif command == "archive":
            with tarfile.open(fileobj=sys.stdout.buffer, mode="w|") as archive:
                for name, content in (("Cargo.toml", b"[workspace]\n"),
                                      ("crates/acp-light-client/Cargo.toml", b"[package]\nname='acp-light-client'\n")):
                    entry = tarfile.TarInfo(name)
                    entry.size = len(content)
                    archive.addfile(entry, io.BytesIO(content))
        else:
            raise AssertionError(args)
    sys.exit(0)
sanitized()
if tool == "rustc":
    print("rustc fixture")
    sys.exit(0)
if tool == "docker":
    if args[0] == "build":
        context = Path(args[-1])
        binary = (context / "runtime-binary").read_bytes()
        target = args[args.index("--target") + 1]
        labels = [args[i + 1] for i, arg in enumerate(args) if arg == "--label"]
        digest = hashlib.sha256(binary).hexdigest()
        assert "org.sourcenetwork.native.binary-sha256=" + digest in labels
        image_id = "sha256:" + hashlib.sha256(binary + target.encode()).hexdigest()
        state.mkdir(exist_ok=True)
        (state / image_id.replace(":", "-")).write_bytes(binary)
        Path(args[args.index("--iidfile") + 1]).write_text(image_id + "\n")
        record("image " + binary.decode().strip())
    elif args[:3] == ["run", "--rm", "--entrypoint"]:
        assert args[3] == "sha256sum"
        binary = (state / args[4].replace(":", "-")).read_bytes()
        digest = "0" * 64 if mode == "bad-image" else hashlib.sha256(binary).hexdigest()
        print(digest + "  " + args[5])
    elif args[:2] == ["run", "--rm"]:
        assert args[-1] == "--help"
        assert (state / args[2].replace(":", "-")).is_file()
    else:
        assert args == ["info"] or args == ["compose", "version"] or args[:2] == ["image", "rm"]
    sys.exit(0)
if tool == "native-shared-suite":
    curve = args[0]
    assert curve in ("bls12-381", "jubjub")
    import re
    manifest = Path("Cargo.toml").read_text()
    assert '[patch."https://github.com/sourcenetwork/backbone.git"]' in manifest
    path = re.search(r'acp-light-client = \{ path = ("[^\n]+") \}', manifest)[1]
    assert Path(json.loads(path)).joinpath("Cargo.toml").is_file()
    for variable, content in (("ORBIS_NATIVE_VERA_IMAGE", "vera normal"),
                              ("ORBIS_NATIVE_IMAGE", curve + " normal"),
                              ("ORBIS_NATIVE_DIAGNOSTIC_IMAGE", curve + " diagnostic")):
        assert (state / os.environ[variable].replace(":", "-")).read_text().strip() == content
    assert "VERAD_BINARY" not in os.environ and "ORBIS_NODE_BINARY" not in os.environ
    assert Path(os.environ["RUNNER_TEMP"]).name == curve
    (Path(os.environ["RUNNER_TEMP"]) / "orbis-native-integration.fixture" / "target").mkdir(parents=True)
    record("shared " + curve)
    print('{"selected_native_scenarios":3}')
    print('{"selected_native_scenarios":1}')
    sys.exit(73 if mode == "shared-failure" else 0)
assert tool == "cargo" and args.pop(0) == "+1.98.0", (tool, args)
command = args.pop(0)
if command == "nextest":
    assert args == ["--version"]
    sys.exit(0)
assert command in ("build", "tree", "test"), command
assert "--manifest-path" in args
if command in ("build", "test"):
    assert "--release" in args and "-j2" in args
release = Path(os.environ["CARGO_TARGET_DIR"]) / "release"
release.mkdir(parents=True, exist_ok=True)
if args[args.index("-p") + 1] == "verad":
    assert command == "build" and "--locked" in args
    (release / "verad").write_text("vera normal\n")
    record("build vera")
else:
    features = args[args.index("--features") + 1]
    curve = features.removeprefix("native,redb,iroh,").removesuffix(",unsafe-testing")
    assert curve in ("bls12-381", "jubjub"), features
    assert "--no-default-features" in args
    kind = "diagnostic" if features.endswith(",unsafe-testing") else "normal"
    if command == "test":
        assert "--locked" in args and args[args.index("--test") + 1] == "native_startup"
        assert Path(os.environ["CARGO_TARGET_DIR"]).parts[-2:] == ("orbis-native-integration.fixture", "target")
        assert "ORBIS_NODE_BINARY" not in os.environ and "VERAD_BINARY" not in os.environ
        assert (state / os.environ["ORBIS_NATIVE_IMAGE"].replace(":", "-")).read_text().strip() == curve + " normal"
        assert (state / os.environ["ORBIS_NATIVE_VERA_IMAGE"].replace(":", "-")).read_text().strip() == "vera normal"
        (release / "orbis-node").write_text("test feature unification\n")
        assert kind == "normal" and "--ignored" in args
        if "--list" in args:
            record("retained-list " + curve)
            print("native_startup_registers_and_preserves_identity_on_restart: test")
            if curve == "bls12-381":
                print("native_defra_signing: test")
        else:
            scenario = args[args.index("--test") + 2]
            assert "--exact" in args and "--test-threads=1" in args and "--nocapture" in args
            assert os.environ["NATIVE_STACK_CURVE"] == curve
            record("retained " + curve + " " + scenario)
            print("test result: ok. 1 passed; 0 failed; 0 ignored;")
    elif command == "build":
        # A diagnostic build overwrites Cargo's shared node output; the normal
        # image must still hold the previously staged production executable.
        (release / "orbis-node").write_text(curve + " " + kind + "\n")
        record("build " + curve + " " + kind)
        print("SECRET_PRIVATE_BUILD_DIAGNOSTIC")
    else:
        assert "--locked" in args and args[args.index("--edges") + 1] == "normal,build"
        assert args[args.index("--prefix") + 1] == "none"
        record("tree " + curve + " " + kind)
        print("cosmrs v0.21.1" if mode == curve else "orbis-node v0.1.0")
