# Verification

Verified on 24 October 2026 with Go 1.27.3.

- `make check`: formatting, `go vet`, and race-enabled integration tests passed.
- `openspec validate --all --strict`: identity specification passed.
- `govulncheck`: zero reachable vulnerabilities. Four advisories exist in required modules but do not affect called code according to this scan.
- Native binary and CGO-disabled Linux amd64 builds passed.
- `docker-compose -f compose.yaml config --quiet`: passed.

The compiled native server was started on localhost with temporary storage. Its initial log contained exactly one administrator P12 password. OpenSSL successfully decrypted the generated bundle. The admin endpoint returned HTTP 401 without a client certificate and HTTP 200 with the imported credential. A process restart reused the same bundle, retained administrator access, and emitted no P12 password. Temporary keys, bundles, database, and credential-bearing logs were deleted after the smoke test.

Integration coverage includes database/output collisions, rollback after ordinary initialization errors, unchanged credentials on restart, P12 password protection, certificate permissions and chain/EKU, CSRF rejection, non-admin access rejection, unregistered/revoked/foreign certificates, OIDC discovery/code exchange/ID-token signatures/UserInfo, invalid PKCE, concurrent code redemption, policy removal, SAML response signature validation, persistent NameID/X.509 context, replay rejection, enforced SP signatures, and accepted/rejected valid/tampered RSA-SHA256 POST and Redirect requests.

## Source layout and container verification

All seven Go implementation/test files now live in `src/`; `go.mod` and `go.sum` remain at the root. Docker builds `./src`, Makefile formatting checks recurse through `src/`, and the native build command in the README targets `./src`. No CI workflow files were present to update. Compose keeps its project-root build context and bind-mount paths.

After relocation, `make check`, `make build`, strict OpenSpec validation, and Compose configuration validation passed. The race-enabled suite reports package `wardstone/src`.

The updated Dockerfile built successfully as `localhost/wardstone:local` with Podman. Public base-image pulls used an empty temporary auth file to avoid an unrelated expired registry credential helper; saved authentication configuration was unchanged.

The built image passed an HTTPS runtime smoke test with temporary host bind mounts, host UID/GID, a read-only root filesystem, dropped capabilities, and no-new-privileges. It created the DB and encrypted administrator P12, logged exactly one bootstrap password, returned HTTP 401 for anonymous admin requests and HTTP 200 for certificate-authenticated requests, and preserved the same P12 and administrator access after container restart without re-logging the password. The temporary test container, mount directories, and credential-bearing output were removed. The built image remains available locally.

No persistent deployment or browser/OS certificate import was performed. Automated protocol tests do not establish OpenID certification, an independent security audit, or interoperability with every downstream application.

## CI/CD implementation checks

The Gitea workflows were validated with actionlint. The delivery specification passes strict OpenSpec validation. Six Python release-tool tests cover semantic version restrictions, reproducible archive metadata, a network-free manual dry run, mismatched tag commits, immutable assets, and completed-release commit checks. The existing Go race suite and module vulnerability check pass, with zero reachable vulnerability findings. All six release binary targets build locally.

The updated Dockerfile builds with native compilation and target OS/architecture build arguments. The portable workflow smoke test passes against Podman using private named volumes and a private network: HTTPS health and mTLS admin return 200, anonymous admin returns 401, and restart reuses the same P12 with one password log. No public product tag, release, or package was created during these checks.
