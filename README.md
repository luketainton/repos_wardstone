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
