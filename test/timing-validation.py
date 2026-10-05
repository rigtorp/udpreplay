#!/usr/bin/env python3
# SPDX-License-Identifier: MIT

import socket
import subprocess
import sys
import time
from pathlib import Path


def loopback_interface():
    for name in ('lo', 'lo0'):
        try:
            if hasattr(socket, 'if_nametoindex') and socket.if_nametoindex(name) != 0:
                return name
        except (OSError, ValueError):
            pass
    return 'lo0' if sys.platform == 'darwin' else 'lo'


TESTS = {
    'constant-interval': (['-c', '1', '-r', '1000'], 3.0),
    'constant-interval-ge1': (['-c', '1001'], 3.0),
    'high-speed': (['-s', '0.1', '-r', '100'], 1.0),
    'low-speed': (['-s', '13', '-r', '1'], 1.3),
    'normal-speed': (['-r', '10'], 1.0),
}


def main():
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <binary> <capture> [test_name]", file=sys.stderr)
        sys.exit(1)

    binary = str(Path(sys.argv[1]).resolve())
    capture = str(Path(sys.argv[2]).resolve())
    selected_test = sys.argv[3] if len(sys.argv) > 3 else None

    if selected_test is not None:
        if selected_test not in TESTS:
            print(f"Unknown test: {selected_test}. Available: {list(TESTS.keys())}", file=sys.stderr)
            sys.exit(1)
        tests_to_run = [(selected_test, *TESTS[selected_test])]
    else:
        tests_to_run = [(name, args, expected) for name, (args, expected) in TESTS.items()]

    iface = loopback_interface()
    for name, args, expected in tests_to_run:
        cmd = [binary, '-i', iface, *args, capture]
        start = time.perf_counter()
        res = subprocess.run(cmd, capture_output=True, text=True)
        elapsed = time.perf_counter() - start

        assert res.returncode == 0, f"{name}: process failed with code {res.returncode}:\n{res.stderr}"
        # Allow ±0.35s tolerance for OS scheduling and timer granularity
        assert abs(elapsed - expected) <= 0.35, (
            f"{name}: expected ~{expected:.2f}s, took {elapsed:.3f}s"
        )
        print(f"{name}: PASS (took {elapsed:.3f}s, expected {expected:.2f}s)")


if __name__ == '__main__':
    main()
