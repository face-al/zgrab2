#!/usr/bin/env python3
"""
Integration test for --starttls, the RFC 2817 upgrade to TLS within HTTP/1.1.

The target container (zgrab_http_starttls) runs CUPS, which answers
"OPTIONS * HTTP/1.1" with "Upgrade: TLS/1.0" on its IPP port 631 with
"101 Switching Protocols", negotiates TLS on the same connection and then
answers the OPTIONS over TLS (RFC 2817, Section 3.3).
"""

import os
import json
import subprocess
import sys


def run_command(command, output_file=None):
    try:
        with subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=True,
        ) as process:
            stdout, stderr = process.communicate()
            if output_file:
                with open(output_file, "w") as f:
                    f.write(stdout)
            if stderr:
                print(stderr, file=sys.stderr)
            return stdout.strip()
    except subprocess.CalledProcessError as e:
        print(f"Command failed: {e}", file=sys.stderr)
        sys.exit(1)


zgrab_root = run_command("git rev-parse --show-toplevel")
zgrab_output = os.path.join(zgrab_root, "zgrab-output")
output_root = os.path.join(zgrab_output, "http")

os.makedirs(output_root, exist_ok=True)

container_name = "zgrab_http_starttls"


def test_starttls():
    """--starttls: CUPS upgrades with 101, TLS completes, OPTIONS answered over TLS."""
    print("http/starttls_test: --starttls should upgrade to TLS")
    output_file = os.path.join(output_root, "http_starttls.json")
    raw = run_command(
        f"CONTAINER_NAME={container_name} "
        f"{zgrab_root}/docker-runner/docker-run.sh "
        f"http --port 631 --starttls",
        output_file=output_file,
    )

    scan = json.loads(raw).get("data", {}).get("http", {})
    status = scan.get("status")
    assert status == "success", f"Expected scan status 'success', got '{status}': {scan.get('error')}"

    result = scan.get("result", {})
    starttls = result.get("starttls", "")
    assert starttls.startswith(
        "HTTP/1.1 101 "
    ), f"Expected a 101 reply to the upgrade, got {starttls!r}"

    server_hello = result.get("tls", {}).get("handshake_log", {}).get("server_hello")
    assert server_hello, "Expected a TLS server_hello in the tls log"

    status_code = result.get("response", {}).get("status_code")
    assert status_code == 200, f"Expected HTTP 200 over TLS, got {status_code}"

    print("PASS: --starttls upgraded to TLS and got 200 OK over it")


def run_all_tests():
    tests = {
        name: func
        for name, func in globals().items()
        if name.startswith("test_") and callable(func)
    }
    for name, test_func in tests.items():
        print(f"=== Running {name} ===")
        test_func()
        print(f"=== Finished {name} ===\n")


if __name__ == "__main__":
    run_all_tests()
