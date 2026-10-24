## Purpose

Define Wardstone's initial certificate-based identity provider and bootstrap contract.

## Requirements

### Requirement: First boot creates an administrator credential
The system SHALL initialize SQLite only when the database file is absent, create an initial administrator and CA, and export an encrypted administrator PKCS#12 bundle to the configured bootstrap directory. The system SHALL log its random password once on the initialization startup.

#### Scenario: Empty persistent volume
- **WHEN** the database does not exist and the bootstrap output directory is writable
- **THEN** Wardstone creates a mode-0600 database and administrator bundle, exports the public CA, and prints the bundle password to its process log

#### Scenario: Restart
- **WHEN** an initialized database exists
- **THEN** Wardstone reuses persisted identities and keys without issuing another bootstrap credential or logging its password

#### Scenario: Existing incomplete database or output
- **WHEN** a database is empty or unsupported, or an administrator bundle already exists while the DB is absent
- **THEN** startup fails without overwriting the existing credential

### Requirement: Browser identity requires verified mTLS
The system SHALL authenticate browser users only through CA-verified, registered, active client certificate fingerprints and SHALL reject revoked certificates and disabled accounts on every protected request.

#### Scenario: Certificate revocation on an existing connection
- **WHEN** a certificate is revoked while a TLS connection remains open
- **THEN** the next protected request is denied

### Requirement: Application policies deny by default
The system SHALL grant app access only when an active user's current groups intersect that application's allowed groups. Administrator privilege SHALL NOT bypass app policies.

#### Scenario: No matching group
- **WHEN** an administrator or user has no matching allowed group
- **THEN** authorization is denied

### Requirement: OpenID Connect authorization code flow
The system SHALL support registered confidential OIDC clients using exact HTTPS redirect URIs, PKCE S256, one-use expiring codes, and client-secret Basic authentication. Tokens SHALL use persisted federation keys and expire after five minutes. App backchannels SHALL authenticate using their protocol credentials without requiring the user's private certificate.

#### Scenario: Concurrent code redemption
- **WHEN** two requests exchange the same authorization code
- **THEN** at most one exchange succeeds

### Requirement: SAML federation
The system SHALL issue signed RSA SHA-256 SAML assertions and responses only for registered SP metadata and policy-authorized certificate identities. The system SHALL validate signed requests, enforce SP signature requirements, and reject reused request IDs.

#### Scenario: Signed request and registered ACS
- **WHEN** an authorized user presents an SP request with a valid required signature and registered ACS destination
- **THEN** Wardstone returns a verifiable response with persistent user identity and the X.509 authentication context

### Requirement: Protected administration
The system SHALL restrict identity, certificate, application, and group-policy management to certificate-authenticated administrators and SHALL validate CSRF tokens for mutations.

#### Scenario: Missing CSRF token
- **WHEN** an administrator submits a mutation without a valid certificate-bound CSRF token
- **THEN** Wardstone rejects the request without applying the change
