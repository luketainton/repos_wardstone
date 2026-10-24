## Purpose

Expose Wardstone through Pangolin on its existing public HTTPS hostname while retaining native client-certificate authentication.

## Requirements

### Requirement: Preserve the public origin and native mTLS
Traefik SHALL route TLS for cba.tainton.uk on port 443 to Wardstone's existing HTTPS listener using TCP TLS passthrough. Wardstone SHALL request and verify the browser client certificate itself. Pangolin mTLS SHALL remain disabled.

#### Scenario: Browser certificate login through the gateway
- **WHEN** a browser connects to the public origin with a registered active client certificate
- **THEN** Wardstone receives and verifies that certificate and grants administrator access according to its existing authorization rules

### Requirement: Separate server TLS and client identity
Wardstone SHALL use the exported public server certificate and key through a read-only mount. Deployment SHALL preserve the existing database, client CA, client certificates, and bootstrap bundle.

#### Scenario: Change the server certificate
- **WHEN** Wardstone switches to the publicly trusted server certificate
- **THEN** its existing administrator P12 remains valid without regeneration

### Requirement: Validated certificate renewal
The exporter SHALL validate hostname, key pairing, and at least 24 hours of remaining validity before replacing files. It SHALL restrict private-key access, serialize exports, and restart only a running Wardstone whose loaded certificate differs from the validated export.

#### Scenario: Invalid incoming material
- **WHEN** ACME material is missing, mismatched, or invalid
- **THEN** the exporter preserves the existing certificate/key and does not restart Wardstone

#### Scenario: Unchanged certificate or stopped app
- **WHEN** the loaded certificate matches the export or the container is stopped
- **THEN** no restart or container start occurs

### Requirement: Scoped and recoverable routing
Deployment SHALL preserve existing HTTP routers and provide timestamped backups of edited live configuration. It SHALL NOT require DNS, firewall, public-port, or application-code changes.

#### Scenario: Other public hostnames
- **WHEN** traffic uses a hostname other than cba.tainton.uk
- **THEN** the new TCP route does not match and existing HTTP routing continues
