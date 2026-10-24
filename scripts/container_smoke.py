#!/usr/bin/env python3
"""Verify bootstrap, mTLS, and restart using private Docker volumes and network."""
import argparse
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="wardstone:ci")
    parser.add_argument("--engine", default="docker")
    args = parser.parse_args()

    def engine(*cmd, data=None):
        result = subprocess.run([args.engine, *cmd], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if result.returncode:
            # Logs contain the bootstrap password. Never include their contents in an error.
            raise RuntimeError(f"Container command {cmd[0]} failed (exit {result.returncode})")
        return result.stdout + result.stderr if cmd[0] == "logs" else result.stdout

    suffix = uuid.uuid4().hex[:12]
    name, network = f"wardstone-smoke-{suffix}", f"wardstone-net-{suffix}"
    volumes = [f"wardstone-data-{suffix}", f"wardstone-bootstrap-{suffix}"]
    helper = name + "-client"
    cleanup = []
    try:
        engine("network", "create", network)
        cleanup.append(("network", "rm", network))
        for volume in volumes:
            engine("volume", "create", volume)
            cleanup.append(("volume", "rm", volume))
        engine("run", "-d", "--pull=never", "--name", name, "--network", network, "--network-alias", "wardstone-smoke", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "-e", "WARDSTONE_ISSUER=https://wardstone-smoke:8443", "-v", volumes[0] + ":/data", "-v", volumes[1] + ":/bootstrap", args.image)
        cleanup.append(("rm", "-f", name))

        def password(expected_starts=1):
            for _ in range(120):
                logs = engine("logs", name)
                matches = re.findall(r"BOOTSTRAP administrator P12 password: (\S+)", logs)
                if matches and logs.count("Wardstone listening") >= expected_starts:
                    if len(matches) != 1:
                        raise RuntimeError("Bootstrap password logged more than once")
                    return matches[0]
                if engine("inspect", "--format", "{{.State.Running}}", name).strip() != "true":
                    raise RuntimeError("Server exited before HTTPS readiness")
                time.sleep(0.5)
            raise RuntimeError("Server readiness timeout (60 seconds)")

        initial_password = password()
        architecture = engine("image", "inspect", "--format", "{{.Architecture}}", args.image).strip()
        if architecture not in ("amd64", "arm64"):
            raise RuntimeError("Unsupported smoke-test architecture")
        with tempfile.TemporaryDirectory(prefix="wardstone-client-") as temp:
            binary = Path(temp) / "smoke-client"
            subprocess.run(["go", "build", "-trimpath", "-o", str(binary), "./src/smokeclient"], env=dict(os.environ, GOOS="linux", GOARCH=architecture, CGO_ENABLED="0"), check=True)
            for phase in ("first boot", "restart"):
                if phase == "restart":
                    engine("stop", "--time", "10", name)
                    engine("start", name)
                    if password(expected_starts=2) != initial_password:
                        raise RuntimeError("Bootstrap credential changed on restart")
                engine("create", "--interactive", "--pull=never", "--name", helper, "--network", network, "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "-v", volumes[1] + ":/bootstrap:ro", "--entrypoint", "/smoke-client", args.image)
                cleanup.append(("rm", "-f", helper))
                engine("cp", str(binary), helper + ":/smoke-client")
                print(phase + ": " + engine("start", "--attach", "--interactive", helper, data=initial_password + "\n").strip())
                exit_code = engine("inspect", "--format", "{{.State.ExitCode}}", helper).strip()
                if exit_code != "0":
                    raise RuntimeError("HTTPS smoke client failed")
                engine("rm", helper)
                cleanup.pop()
        print("PASS: bootstrap and restart retain the same working P12; password logged once")
    finally:
        for cmd in reversed(cleanup):
            subprocess.run([args.engine, *cmd], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        raise SystemExit(str(error)) from None
