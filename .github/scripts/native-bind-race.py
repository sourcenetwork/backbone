#!/usr/bin/env python3
"""Recognize only the retained evidence for a native-cluster RPC bind race."""
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
TIMEOUT = (
    "called `Result::unwrap()` on an `Err` value: "
    "timeout (30s) waiting for 4 nodes to become healthy"
)
PANIC = re.compile(r"\bpanicked\b|\bassertion\b.*\bfailed\b", re.IGNORECASE)


def read(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError("missing regular evidence file")
    return ANSI.sub("", path.read_text())


def confirmed(attempt, scenario):
    output = read(attempt / "command.log")
    lines = output.splitlines()
    panics = [i for i, line in enumerate(lines) if "panicked at" in line]
    if len(panics) != 1:
        return False
    index = panics[0]
    if not re.fullmatch(
        r"thread '" + re.escape(scenario) + r"' \(\d+\) panicked at .+:", lines[index]
    ):
        return False
    if index + 1 >= len(lines) or lines[index + 1] != TIMEOUT:
        return False
    if any(PANIC.search(line) for i, line in enumerate(lines) if i != index):
        return False
    if lines.count("running 1 test") != 1 or not re.search(
        r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored;", output, re.MULTILINE
    ):
        return False
    clusters = list((attempt / "clusters").iterdir())
    if len(clusters) != 1 or not clusters[0].is_dir() or clusters[0].is_symlink():
        return False
    nodes = sorted(clusters[0].glob("node*"))
    if [node.name for node in nodes] != ["node0", "node1", "node2", "node3"]:
        return False
    collision = False
    for node in nodes:
        node_collision = False
        for name in ("stdout.log", "stderr.log"):
            for line in read(node / "logs" / name).splitlines():
                if PANIC.search(line):
                    return False
                bind = (
                    "ERROR vera_jsonrpc::server: Failed to build JSON-RPC server" in line
                    and "Address already in use" in line
                )
                stopped_after_bind = node_collision and line.endswith(
                    "ERROR vera_node::node: RPC server stopped unexpectedly"
                )
                if re.search(r"\bERROR\b", line) and not bind and not stopped_after_bind:
                    return False
                node_collision |= bind
                collision |= bind
    return collision


if __name__ == "__main__":
    try:
        valid = len(sys.argv) == 3 and confirmed(Path(sys.argv[1]), sys.argv[2])
    except (OSError, UnicodeError, ValueError):
        valid = False
    sys.exit(0 if valid else 1)
