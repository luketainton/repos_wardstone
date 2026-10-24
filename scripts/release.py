#!/usr/bin/env python3
"""Build deterministic release archives and publish them through the Gitea API."""

import argparse
import datetime as dt
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile

TAG = re.compile(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\Z")
TARGETS = [(system, arch) for system in ("linux", "darwin", "windows") for arch in ("amd64", "arm64")]
MANIFEST = "release-manifest.json"


def version(tag):
    match = TAG.fullmatch(tag)
    if not match or any(p.isdigit() and len(p) > 1 and p.startswith("0") for p in (match[4] or "").split(".")):
        raise ValueError("Use vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-prerelease (no build metadata)")
    return tuple(map(int, match.group(1, 2, 3))), bool(match[4])


def command(*args, **kwargs):
    return subprocess.check_output(args, text=True, **kwargs).strip()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class API:
    def __init__(self, server, repository, token):
        parsed = urllib.parse.urlsplit(server)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path not in ("", "/"):
            raise ValueError("Gitea server must be an HTTPS origin")
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository):
            raise ValueError("Invalid repository name")
        self.server = server.rstrip("/")
        self.repo = f"/repos/{repository}"
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect)

    def request(self, path, *, method="GET", data=None, content_type=None, missing=False, raw=False):
        headers = {"Accept": "application/json", "User-Agent": "wardstone-release"}
        if self.token:
            headers["Authorization"] = f"token {self.token}"
        if isinstance(data, dict):
            data = json.dumps(data).encode()
            content_type = "application/json"
        if content_type:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.server + "/api/v1" + path, data=data, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=120) as response:
                body = response.read()
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError(f"Gitea {method} {path}: HTTP {error.code}") from None
        return body if raw else json.loads(body) if body else None

    def release(self, tag):
        return self.request(self.repo + "/releases/tags/" + urllib.parse.quote(tag, safe=""), missing=True)

    def assets(self, release_id):
        assets = []
        for page in range(1, 100):
            items = self.request(f"{self.repo}/releases/{release_id}/assets?limit=100&page={page}")
            assets.extend(items)
            if len(items) < 100:
                return assets
        raise RuntimeError("Too many release assets")

    def download(self, asset):
        # Never forward a publishing token to a redirect or a different origin.
        url = asset["browser_download_url"]
        if not url.startswith(self.server + "/"):
            raise RuntimeError("Refusing off-origin asset download")
        headers = {"Authorization": f"token {self.token}"} if self.token else {}
        with self.opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
            return response.read()

    def completed(self, release, commit):
        if not release:
            return False
        markers = [a for a in self.assets(release["id"]) if a["name"] == MANIFEST]
        if not markers:
            return False
        manifest = json.loads(self.download(markers[0]))
        if manifest.get("commit") != commit:
            raise RuntimeError("Release already contains artifacts for another commit; never move a release tag")
        return manifest.get("complete") is True

    def upload(self, release_id, name, body, existing):
        if name in existing:
            if hashlib.sha256(self.download(existing[name])).digest() != hashlib.sha256(body).digest():
                raise RuntimeError(f"Refusing to replace an existing release asset with different contents: {name}")
            return
        boundary = "wardstone-" + hashlib.sha256(body).hexdigest()
        multipart = (f'--{boundary}\r\nContent-Disposition: form-data; name="attachment"; filename="{name}"\r\nContent-Type: application/octet-stream\r\n\r\n').encode() + body + f"\r\n--{boundary}--\r\n".encode()
        self.request(f"{self.repo}/releases/{release_id}/assets?name=" + urllib.parse.quote(name), method="POST", data=multipart, content_type=f"multipart/form-data; boundary={boundary}")


def outputs(values):
    path = os.environ.get("GITHUB_OUTPUT") or os.environ.get("GITEA_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            for key, value in values.items():
                value = str(value).lower() if isinstance(value, bool) else str(value)
                if "\n" in value or "\r" in value:
                    raise ValueError("Invalid workflow output")
                stream.write(f"{key}={value}\n")


def plan(args):
    event = json.loads(Path(os.environ.get("GITHUB_EVENT_PATH", os.environ.get("GITEA_EVENT_PATH", "/dev/null"))).read_text() or "{}")
    name = os.environ.get("GITHUB_EVENT_NAME", os.environ.get("GITEA_EVENT_NAME", "workflow_dispatch"))
    inputs = event.get("inputs", {})
    publish = name in ("push", "release") or str(inputs.get("publish", "false")).lower() == "true"
    tag = event.get("release", {}).get("tag_name") or inputs.get("tag")
    if not tag and name == "push":
        ref = os.environ.get("GITHUB_REF", os.environ.get("GITEA_REF", ""))
        if not ref.startswith("refs/tags/"):
            raise ValueError("Publishing requires a tag event")
        tag = ref.removeprefix("refs/tags/")
    if not tag:
        if publish:
            raise ValueError("Publishing requires an existing version tag")
        tag = "v0.0.0-ci." + str(os.environ.get("GITHUB_RUN_NUMBER", "0"))
    _, prerelease = version(tag)
    commit = command("git", "rev-parse", "HEAD")
    if publish or inputs.get("tag"):
        tagged = command("git", "rev-parse", f"refs/tags/{tag}^{{commit}}")
        if tagged != commit:
            raise ValueError("Checked-out commit does not match the release tag")
    epoch = command("git", "show", "-s", "--format=%ct", "HEAD")
    date = dt.datetime.fromtimestamp(int(epoch), dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    server = os.environ.get("GITHUB_SERVER_URL", "https://git.tainton.uk").rstrip("/")
    repo = os.environ.get("GITHUB_REPOSITORY", "repos/wardstone")
    image = urllib.parse.urlsplit(server).netloc + "/" + repo.lower()
    skip = False
    username = ""
    registry_token = os.environ.get("REGISTRY_TOKEN", "")
    if registry_token:
        registry_api = API(server, repo, registry_token)
        username = registry_api.request("/user")["login"]
        registry_api.request("/packages/" + repo.split("/")[0] + "?type=container&limit=1")
        API(server, repo, os.environ.get("RELEASE_TOKEN", "")).request("/repos/" + repo + "/releases?limit=1")
    if publish:
        if not registry_token:
            raise RuntimeError("ACTIONS_TOKEN must have package write permission")
        api = API(server, repo, os.environ.get("RELEASE_TOKEN", ""))
        release = api.release(tag)
        skip = bool(release and not release["draft"] and api.completed(release, commit))
        prerelease = prerelease or bool(release and release["prerelease"])
    values = dict(tag=tag, commit=commit, build_date=date, epoch=epoch, image=image, registry=urllib.parse.urlsplit(server).netloc, registry_user=username, publish=publish, skip=skip, prerelease=prerelease)
    outputs(values)
    print(json.dumps({k: v for k, v in values.items() if k != "registry_user"}, sort_keys=True))


def archive(path, files, epoch):
    if path.suffix == ".zip":
        timestamp = dt.datetime.fromtimestamp(max(epoch, 315532800), dt.timezone.utc).timetuple()[:6]
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as out:
            for name, body, mode in files:
                info = zipfile.ZipInfo(name, timestamp)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = mode << 16
                out.writestr(info, body)
    else:
        with path.open("wb") as raw, gzip.GzipFile(filename="", fileobj=raw, mode="wb", mtime=epoch) as compressed, tarfile.open(fileobj=compressed, mode="w") as out:
            for name, body, mode in files:
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(body), mode, epoch
                out.addfile(info, io.BytesIO(body))


def build(args):
    version(args.tag)
    output = Path(args.output)
    output.mkdir(parents=True, exist_ok=True)
    if any(output.iterdir()):
        raise ValueError("Release output directory must be empty")
    commit = command("git", "rev-parse", "HEAD")
    epoch = int(command("git", "show", "-s", "--format=%ct", "HEAD"))
    date = dt.datetime.fromtimestamp(epoch, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    flags = f"-s -w -X main.version={args.tag} -X main.commit={commit} -X main.buildDate={date}"
    for system, arch in TARGETS:
        binary = "wardstone.exe" if system == "windows" else "wardstone"
        target = output / f".wardstone-{system}-{arch}"
        subprocess.run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags", flags, "-o", str(target), "./src"], env=dict(os.environ, CGO_ENABLED="0", GOOS=system, GOARCH=arch), check=True)
        ext = ".zip" if system == "windows" else ".tar.gz"
        files = [(binary, target.read_bytes(), 0o755), ("README.md", Path("README.md").read_bytes(), 0o644)]
        archive(output / f"wardstone-{args.tag}-{system}-{arch}{ext}", files, epoch)
        target.unlink()
    sums = "".join(f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.name}\n" for p in sorted(output.iterdir()))
    (output / "SHA256SUMS").write_text(sums)
    print(f"Built {len(TARGETS)} archives and SHA256SUMS in {output}")


def publish(args):
    semver, prerelease = version(args.tag)
    commit = command("git", "rev-parse", "HEAD")
    if command("git", "rev-parse", f"refs/tags/{args.tag}^{{commit}}") != commit:
        raise ValueError("Refusing publication from a different commit")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", args.digest):
        raise ValueError("A valid published image digest is required")
    server = os.environ["GITHUB_SERVER_URL"].rstrip("/")
    repo = os.environ["GITHUB_REPOSITORY"]
    expected_image = urllib.parse.urlsplit(server).netloc + "/" + repo.lower()
    if args.image != expected_image:
        raise ValueError("Unexpected container registry/repository")
    token = os.environ.get("RELEASE_TOKEN", "")
    if not token:
        raise RuntimeError("Release write token is required")
    api = API(server, repo, token)
    release = api.release(args.tag)
    if release and api.completed(release, commit):
        if release["draft"]:
            api.request(f"{api.repo}/releases/{release['id']}", method="PATCH", data={"draft": False})
        print("Release artifacts already complete; preserved existing assets")
        return
    if not release:
        release = api.request(api.repo + "/releases", method="POST", data={"tag_name": args.tag, "target_commitish": commit, "name": args.tag, "body": f"Wardstone {args.tag}\n\nContainer: `{args.image}:{args.tag}`\n\nVerify downloaded archives with `sha256sum -c SHA256SUMS`.", "draft": True, "prerelease": prerelease})
    prerelease = prerelease or release["prerelease"]
    output = Path(args.output)
    expected = {f"wardstone-{args.tag}-{system}-{arch}" + (".zip" if system == "windows" else ".tar.gz") for system, arch in TARGETS} | {"SHA256SUMS"}
    if {p.name for p in output.iterdir()} != expected:
        raise ValueError("Release output must contain exactly the six archives and SHA256SUMS")
    recorded = dict((name, digest) for digest, name in (line.split("  ", 1) for line in (output / "SHA256SUMS").read_text().splitlines()))
    for name in expected - {"SHA256SUMS"}:
        if recorded.get(name) != hashlib.sha256((output / name).read_bytes()).hexdigest():
            raise ValueError("Archive checksum mismatch")
    existing = {a["name"]: a for a in api.assets(release["id"])}
    for name in sorted(expected):
        api.upload(release["id"], name, (output / name).read_bytes(), existing)
    # Promote only the newest stable version. An older tag retry cannot roll latest back.
    promote = not prerelease
    if promote:
        for page in range(1, 100):
            releases = api.request(api.repo + f"/releases?limit=100&page={page}")
            for item in releases:
                try:
                    other, preview = version(item["tag_name"])
                except ValueError:
                    continue
                if not item["draft"] and not item["prerelease"] and not preview and other > semver:
                    promote = False
            if len(releases) < 100:
                break
        else:
            raise RuntimeError("Release listing exceeded pagination limit")
    if promote:
        subprocess.run(["docker", "buildx", "imagetools", "create", "--tag", args.image + ":latest", args.image + "@" + args.digest], check=True)
    marker = json.dumps({"tag": args.tag, "commit": commit, "image": args.image, "digest": args.digest, "complete": True}, indent=2, sort_keys=True).encode() + b"\n"
    api.upload(release["id"], MANIFEST, marker, existing)
    if release["draft"]:
        api.request(f"{api.repo}/releases/{release['id']}", method="PATCH", data={"draft": False})
    print(f"Published {args.tag}: six archives, checksums, manifest and multi-platform image")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    sub.add_parser("plan")
    for action in ("build", "publish"):
        child = sub.add_parser(action)
        child.add_argument("--tag", required=True)
        child.add_argument("--output", default="dist")
        if action == "publish":
            child.add_argument("--image", required=True)
            child.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        {"plan": plan, "build": build, "publish": publish}[args.action](args)
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, str(error) + "\n")


if __name__ == "__main__":
    main()
