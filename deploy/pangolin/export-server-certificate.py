#!/usr/bin/env python3
"""Export Wardstone's server TLS material from Pangolin ACME storage."""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import subprocess
import tempfile
import time


def matches(pattern, hostname):
    pattern, hostname = pattern.lower().rstrip("."), hostname.lower().rstrip(".")
    if pattern.startswith("*."):
        return hostname.endswith(pattern[1:]) and hostname.count(".") == pattern.count(".")
    return pattern == hostname


def material(acme, resolver, hostname):
    candidates = []
    for item in acme.get(resolver, {}).get("Certificates", []):
        names = [item.get("domain", {}).get("main", "")] + item.get("domain", {}).get("sans", [])
        if any(matches(name, hostname) for name in names):
            candidates.append((hostname in names, item))
    if not candidates:
        raise ValueError("No matching server certificate in the selected ACME resolver")
    item = sorted(candidates, key=lambda value: value[0], reverse=True)[0][1]
    try:
        return base64.b64decode(item["certificate"], validate=True), base64.b64decode(item["key"], validate=True)
    except (KeyError, ValueError) as error:
        raise ValueError("Invalid ACME certificate/key encoding") from error


def leaf_fingerprint(pem):
    end = pem.find(b"-----END CERTIFICATE-----")
    if end < 0:
        raise ValueError("Invalid server certificate PEM")
    leaf = pem[:end + len(b"-----END CERTIFICATE-----")].decode("ascii")
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()


def validate(cert_path, key_path, hostname):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(cert_path), str(key_path))
    # Parse SAN DNS names from x509's portable text output. Apple's LibreSSL
    # does not provide OpenSSL's newer -checkhost option.
    check = subprocess.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-text"], capture_output=True, text=True)
    names, in_san = [], False
    for line in check.stdout.splitlines():
        if "X509v3 Subject Alternative Name:" in line:
            in_san = True
            continue
        if in_san and (line.strip().startswith("X509v3 ") or line.strip().startswith("Signature Algorithm:")):
            break
        if in_san:
            names.extend(re.findall(r"DNS:([^,\s]+)", line))
    if check.returncode or not any(matches(name, hostname) for name in names):
        raise ValueError("Server certificate does not match the configured hostname")
    check = subprocess.run(["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "86400"], capture_output=True)
    if check.returncode:
        raise ValueError("Server certificate expires within 24 hours; keeping existing files")


def read_existing(path):
    if path.is_symlink():
        raise ValueError("Refusing a symlink for a server certificate or key")
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def install(path, contents, mode, owner, group):
    fd, temporary = tempfile.mkstemp(prefix=".wardstone-tls-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            os.fchown(stream.fileno(), owner, group)
            stream.write(contents)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def running(container):
    result = subprocess.run(["docker", "inspect", "--format", "{{.State.Running}}", container], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError("Cannot inspect Wardstone container; no restart attempted")
    return result.stdout.strip() == "true"


def live_fingerprint(host, port, hostname):
    # Read only the public certificate from the local listener, including if expired.
    # No credentials or client certificates are sent over this diagnostic connection.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def restart(container):
    result = subprocess.run(["docker", "restart", "--time", "10", container], capture_output=True)
    if result.returncode:
        raise RuntimeError("Wardstone restart failed; the next scheduled check will retry")


@contextlib.contextmanager
def directory_lock(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield descriptor
    finally:
        os.close(descriptor)


def export(args):
    output = Path(args.output_dir)
    if output.is_symlink():
        raise ValueError("Refusing a symlink as the server TLS directory")
    output.mkdir(mode=0o750, parents=True, exist_ok=True)
    os.chown(output, args.owner, args.group)
    os.chmod(output, 0o750)
    # Lock the directory itself: no additional persistent state/lock files are needed.
    with directory_lock(output) as lock:
        acme = json.loads(Path(args.acme_file).read_text())
        certificate, key = material(acme, args.resolver, args.hostname)
        cert_path, key_path = output / "server.crt", output / "server.key"
        previous_cert, previous_key = read_existing(cert_path), read_existing(key_path)
        with tempfile.TemporaryDirectory(prefix=".validate-", dir=output) as staging:
            staged_cert, staged_key = Path(staging) / "server.crt", Path(staging) / "server.key"
            staged_cert.write_bytes(certificate)
            staged_key.write_bytes(key)
            staged_key.chmod(0o600)
            validate(staged_cert, staged_key, args.hostname)
        changed = previous_cert != certificate or previous_key != key
        if changed:
            install(cert_path, certificate, 0o644, args.owner, args.group)
            install(key_path, key, 0o640, args.owner, args.group)
            os.fsync(lock)
        else:
            for path, mode in ((cert_path, 0o644), (key_path, 0o640)):
                os.chown(path, args.owner, args.group)
                path.chmod(mode)
        if args.no_restart or not running(args.container):
            return changed, False
        target = leaf_fingerprint(certificate)
        try:
            loaded = live_fingerprint(args.backend_host, args.backend_port, args.hostname)
        except OSError:
            if not changed:
                raise RuntimeError("Cannot check Wardstone's loaded certificate; no restart attempted") from None
            loaded = None
        if loaded == target:
            return changed, False
        restart(args.container)
        for _ in range(20):
            try:
                if live_fingerprint(args.backend_host, args.backend_port, args.hostname) == target:
                    return changed, True
            except OSError:
                pass
            time.sleep(0.5)
        raise RuntimeError("Wardstone has not loaded the exported certificate; next check will retry")


def parser():
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--acme-file", default="/docker/pangolin/data/proxy/lecerts/acme.json")
    result.add_argument("--resolver", default="letsencrypt")
    result.add_argument("--hostname", default="cba.tainton.uk")
    result.add_argument("--output-dir", default="/docker/cba/app/tls")
    result.add_argument("--owner", type=int, default=0)
    result.add_argument("--group", type=int, default=10001)
    result.add_argument("--container", default="cba-app-1")
    result.add_argument("--backend-host", default="172.17.0.1")
    result.add_argument("--backend-port", type=int, default=18471)
    result.add_argument("--no-restart", action="store_true")
    return result


def main():
    cli = parser()
    try:
        changed, restarted = export(cli.parse_args())
        if changed or restarted:
            print("Wardstone server TLS export complete; certificate updated=" + str(changed) + ", container restarted=" + str(restarted))
    except (OSError, ValueError, RuntimeError) as error:
        cli.exit(1, "Wardstone TLS export failed: " + str(error) + "\n")


if __name__ == "__main__":
    main()
