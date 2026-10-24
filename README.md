# Wardstone

Certificate-bound identity. Policy-defined access.

Wardstone is a Go OIDC/SAML identity provider with a built-in client CA. Users authenticate with registered mTLS certificates. Membership in any of an application's allowed groups grants access; an empty policy denies everyone, including administrators.

This is an initial implementation, not a conformance-certified or independently audited identity provider.

## First boot with Docker Compose

Run from the project directory:

```sh
mkdir -p data bootstrap
chmod 700 data bootstrap
export WARDSTONE_UID="$(id -u)"
export WARDSTONE_GID="$(id -g)"
docker compose up --build -d
docker compose logs wardstone
```

Compose runs as your host UID/GID so the bind mounts are writable. Keep those environment values in a local `.env` for later Compose invocations. Neither `.env` nor runtime state belongs in source control.

On the first boot, when `/data/wardstone.db` is absent, Wardstone:

1. Creates SQLite storage, a client CA, a separate federation signing key, and an HTTPS server certificate.
2. Creates the `administrator` account in the `administrators` group.
3. Writes `/bootstrap/administrator.p12` with its private key, certificate, and CA chain, protected by a random 32-character password.
4. Exports the public CA certificate to `/bootstrap/ca.crt` and prints the P12 password once in the startup log.

Import `bootstrap/administrator.p12` into your browser/OS certificate store using that password. Trust `bootstrap/ca.crt` for the generated localhost server certificate, then open **https://localhost:8443/admin** and select the administrator certificate. Do not bypass certificate validation for normal use.

The P12 and database are created with mode `0600`; newly created directories use `0700`. Only the initial P12 password is intentionally logged. The password is not stored in the database or written to a separate password file. Treat container logs as credential-bearing until your administrator certificate is replaced and the bootstrap certificate is revoked.

Subsequent boots preserve the database, CA, signing keys, account, and existing P12. They do not regenerate credentials or log a new password. An existing empty/corrupt/unsupported database fails closed. A pre-existing `administrator.p12` prevents initialization from overwriting it. Ordinary initialization errors roll back the new DB and bundle. A process/power failure during initialization can leave partial state: startup refuses to silently replace it. Preserve the files and inspect before recovery.

Keep the password or imported private key safe. Losing both does not trigger another bootstrap. This version has no unauthenticated recovery endpoint. Back up the database and bootstrap bundle to protected storage; the database contains CA and signing private keys. A running SQLite backup should use SQLite's backup facilities rather than copying a file during writes.

## Project layout

Go implementation and integration tests live in `src/`. The Go module files, Dockerfile, Compose configuration, Makefile, and documentation stay at the project root. Run build and test commands from the root; the executable package is `./src`.

## Native development

```sh
go test -race ./...
go build -o wardstone ./src
WARDSTONE_DATA_DIR=./data WARDSTONE_BOOTSTRAP_DIR=./bootstrap \
  WARDSTONE_ISSUER=https://localhost:8443 ./wardstone
```

The first-boot password is generated locally at runtime. Tests use temporary databases and certificates and never print bootstrap passwords.

## Manage identity and access

Use `/admin` to add users, assign comma-separated groups, issue client P12 bundles, revoke certificates, and register applications. Later P12 downloads use an administrator-supplied password of at least 16 characters. Private keys are returned only in the encrypted bundle; user private keys are not retained in SQLite.

Register an application and specify its allowed groups. Policies match any listed group. Users without a matching group cannot authenticate to that app. Administrator status grants admin UI access, not automatic access to applications. User memberships and app policies can be updated in the UI.

Certificates are matched by their SHA-256 fingerprint against the database, not by a user-controlled common name. Every browser request checks certificate registration, expiry, revocation, and account status, including reused TLS connections. The CA signature alone does not grant access. Forwarded certificate headers are never trusted.

To rotate an administrator credential, issue another certificate for that administrator, import it, open a fresh browser connection using it, then revoke the old certificate. The UI prevents revoking the currently administering certificate and does not permit administrator account disabling in this version. Non-admin users can be disabled; account re-enabling is not yet exposed in the UI.

## OpenID Connect

Discovery: `https://localhost:8443/.well-known/openid-configuration`

Register the application's exact HTTPS redirect URI, a random client secret of at least 32 characters, and allowed groups. Copy the client ID shown in the admin UI and retain the secret you supplied. Secrets are stored as SHA-256 digests; this assumes high-entropy random client secrets, not human passwords.

Supported: confidential web clients, authorization code flow, mandatory PKCE S256, `client_secret_basic`, RS256 ID tokens, opaque access tokens, UserInfo, introspection, and revocation. Scopes: `openid`, `profile`, `email`, and `groups`. Email addresses are administrator assertions and are not marked verified. Codes expire in five minutes and can be redeemed once; concurrent redemption is serialized by SQLite. ID/access tokens expire in five minutes. Refresh tokens, dynamic registration, public/native clients, request objects, interactive consent, and requested ACR selection are not supported. Group policy represents administrator-managed consent for registered applications.

Browser authorization, callback, login, logout, and management routes require a valid user certificate. Discovery, public keys, token exchange, UserInfo, introspection, revocation, CA download, health, and SAML metadata do not require the user's certificate: applications use their client secret or bearer token on the relevant backchannels. This permits standard OIDC integrations without installing user private keys into each application. Access tokens are bearer tokens, not RFC 8705 certificate-bound tokens.

Policy, account, and certificate status are checked during authorization, code redemption, UserInfo, and introspection. Already issued ID tokens and sessions established inside downstream applications remain subject to their expiry/application session rules. Revoking a certificate does not remotely log a user out of every application.

## SAML 2.0

Metadata: `https://localhost:8443/saml/metadata`; SSO: `https://localhost:8443/saml/sso`.

Paste each application's SP `EntityDescriptor` metadata in the admin UI and assign allowed groups. The entity ID becomes the application's ID. ACS destinations must use HTTPS and are checked against registered metadata. Metadata is supplied directly; Wardstone never fetches arbitrary administrator-provided URLs.

Supports SP-initiated HTTP-Redirect and HTTP-POST requests and HTTP-POST responses. Response and assertion signatures use RSA SHA-256, with the X.509 authentication context and a persistent user UUID NameID. SAML usernames, email, and groups are drawn from the user record. Replay IDs are persisted. Signed requests are validated against the registered SP signing certificates; metadata requiring signed requests is enforced. Request signing supports RSA SHA-256, with SHA-256 XML digests. A requested authentication context must be exact X.509. Artifact binding, single logout, unsolicited IdP-initiated login, other signature algorithms, and generalized authentication-context negotiation are not supported.

## Deployment configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WARDSTONE_DATA_DIR` | `/data` | Persistent database and private key storage |
| `WARDSTONE_BOOTSTRAP_DIR` | `/bootstrap` | Initial P12 and public CA export |
| `WARDSTONE_ISSUER` | `https://localhost:8443` | Public HTTPS origin, no trailing slash/path |
| `WARDSTONE_LISTEN` | `:8443` | Native TLS listener |
| `WARDSTONE_TLS_CERT`, `WARDSTONE_TLS_KEY` | unset | Optional PEM server certificate chain and private key; both required together |

The included Compose file binds to `127.0.0.1:8443` by default. For remote deployment set `WARDSTONE_BIND_ADDRESS` and `WARDSTONE_ISSUER`. Set the issuer correctly before the first boot because the generated server certificate is issued for that hostname. A supplied server certificate can be publicly trusted while the client CA remains private; mount its files read-only and pass both TLS variables. The generated development server certificate lasts one year; automatic server/CA/signing-key rotation is not implemented.

Wardstone must terminate client TLS itself. Use direct HTTPS or TCP/TLS passthrough at your proxy. Terminating mTLS at an HTTP reverse proxy and forwarding certificate headers is unsupported. TLS 1.3 is required. The container runs without Linux capabilities and with a read-only root filesystem; only the data and bootstrap mounts need writes.

`GET /healthz` checks database connectivity. Run `make check` for formatting, vetting, and the race-enabled integration suite. The implementation targets one process using local SQLite; clustered deployments and distributed CA/key custody are outside this version's scope.

## CI and releases

Gitea Actions workflows live in `.gitea/workflows/`. CI runs on branch pushes, pull requests, and manual dispatch. It checks module integrity, formatting, vet, race-enabled tests, release-tooling tests, reachable Go vulnerabilities, standalone builds, and an HTTPS container smoke test. The smoke test uses temporary private Docker volumes and a network, keeps bootstrap passwords out of CI output, and removes its containers and volumes afterwards.

Published Gitea releases are the sole automatic trigger for the full `Release` build. A separate lightweight `Prepare release` workflow handles version-tag creation, whether the tag is pushed through Git or created in Gitea UI/API. It creates a published release entry only if one is absent, which triggers the full build once. Creating a tag therefore produces one short preparation run plus one full release build, rather than three full release runs. The redundant tag-push build trigger is removed.

If the tag already has a published release or a manually created draft, preparation leaves it unchanged: existing notes and draft status are preserved. Publishing that draft later triggers the full build. Concurrent tag/release creation is handled by rechecking for the release if the creation request loses the race. The preparation workflow deliberately uses the inherited `ACTIONS_TOKEN` PAT: Gitea suppresses follow-on workflow events from its built-in job token. The full release workflow continues to use its built-in token for attachments and finalization.

Use immutable semantic-version tags such as `v0.1.0` or `v0.2.0-rc.1`; build metadata (`+...`) is deliberately unsupported because it is not a valid OCI tag. The checked-out commit must match the tag. For tag-only publishing, the release entry is visible while its artifacts build; binaries and the container manifest appear when the build succeeds. Existing release notes are preserved.

Each release contains six archives: Linux/macOS/Windows, each for amd64 and arm64, plus `SHA256SUMS` and `release-manifest.json`. Archives contain the executable and README. Build version, commit, and date are embedded; run `wardstone --version` to inspect them. Archive metadata uses the commit timestamp for reproducibility.

Images are published to `git.tainton.uk/repos/wardstone:<tag>` for `linux/amd64` and `linux/arm64`. Only the newest stable version promotes `:latest`; prereleases and older stable releases do not move it. The release manifest records the exact image digest. Do not move existing tags: a completed release for another commit fails closed. Completed same-commit reruns skip publication. Partial retries reuse identical assets and refuse to overwrite assets whose contents differ. Release jobs serialize publication across versions.

The repository inherits `ACTIONS_TOKEN` from the `repos` organization. This personal access token needs package write permission and access to organization packages. The workflow resolves its username through Gitea and uses it only for registry authentication. Gitea's built-in job token, requested with `contents: write`, creates releases and uploads attachments. No plaintext credentials belong in repository files. If repository/organization maximum token permissions are later restricted, retain release write access for the release job. Third-party actions are pinned to commit hashes.

To rehearse the pipeline, open Actions → Release → Run workflow, leave `tag` empty and `publish` false. It builds the selected branch, tests the container, builds all archives, and exports a multi-platform OCI image on the runner without publishing any release/tag/package. A manual publish requires an existing tag and `publish` true. Download artifacts from a completed Gitea release and verify with `sha256sum -c SHA256SUMS` (macOS: `shasum -a 256 -c SHA256SUMS`).

For local packaging, run `python3 scripts/release.py build --tag v0.1.0 --output dist` from the repository root (the tag here is an example). For a local container test run `python3 scripts/container_smoke.py --image wardstone:ci`; Podman users can pass `--engine podman`. The Docker engine must be available, and Go must be installed to compile the small HTTPS smoke client.

To use a published image with the supplied Compose file, export `WARDSTONE_IMAGE=git.tainton.uk/repos/wardstone:<tag>`, retain the UID/GID and bind-mount setup above, run `docker compose pull`, then `docker compose up -d --no-build`. Releases deliver artifacts and images; they do not automatically restart an unspecified deployment.

## Pangolin TLS passthrough

For `cba.tainton.uk` on port 443, see [the deployment and rollback guide](deploy/pangolin/README.md). It documents the hostname-specific TCP route, the separately exported server certificate, the read-only Compose mount, and renewal without changing Wardstone client identities or enabling Pangolin mTLS.
