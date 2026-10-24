# Wardstone through Pangolin on HTTPS port 443

This deployment keeps `https://cba.tainton.uk` while Wardstone requests and verifies browser client certificates itself. Pangolin's HTTP resource remains configured, but Traefik selects the hostname-specific TCP router first and passes the original TLS connection to Wardstone. Pangolin mTLS remains disabled.

## Files and prerequisites

- Pangolin's active file-provider configuration: `/docker/pangolin/data/proxy/config/dynamic_config.yml` (container path `/etc/traefik/dynamic_config.yml`). The existing `websecure` entry point listens on port 443.
- Wardstone's existing listener: `172.17.0.1:18471`, published to container port 8443. Its issuer remains `https://cba.tainton.uk`.
- Pangolin ACME storage: `/docker/pangolin/data/proxy/lecerts/acme.json`, resolver `letsencrypt`, holding the existing `*.tainton.uk` certificate.
- Wardstone runs as UID/GID 10001. Host-side export requires root, Python 3, OpenSSL, and Docker. Do not commit/export ACME contents or private key contents into Git, logs, or chat.

The wildcard server key will be readable by Wardstone. This is server TLS material, separate from Wardstone's client CA and administrator P12. Certificate/key files are exported to `/docker/cba/app/tls` (directory root:10001 mode 0750; key root:10001 mode 0640; public chain mode 0644), mounted read-only in the container.

## Rollout

1. Merge the deployment assets PR, review the separate `composeds1/cba` Compose PR, and back up the current Traefik dynamic file and `/home/deploy/cba/compose.yaml` with timestamped names. Install `export-server-certificate.py` as root-owned mode-0755 `/usr/local/sbin/wardstone-export-server-certificate`.
2. Run `sudo /usr/local/sbin/wardstone-export-server-certificate --no-restart`. It selects a matching ACME certificate, validates hostname, lifetime and key pairing, and exports it without restarting the existing app. Existing valid files survive validation errors. No password or private key content is printed.
3. Merge/deploy the Compose PR. It adds `${PROJECT_DATA_FOLDER}/app/tls:/tls:ro`, `WARDSTONE_TLS_CERT=/tls/server.crt`, and `WARDSTONE_TLS_KEY=/tls/server.key`. Recreate only Wardstone. Verify its local listener presents the exported certificate, while the database and administrator certificate stay unchanged.
4. Merge the `tcp` section in `wardstone-tcp.yaml` into the existing dynamic file. Preserve its current `http` section and any other configuration. Use a temporary file and atomic rename, retaining permissions. The file provider hot-reloads this change; no Pangolin stack restart, firewall, DNS, public-port, or Pangolin authentication change is needed.
5. Install `wardstone-tls.cron` as root-owned mode-0644 `/etc/cron.d/wardstone-tls`, after confirming direct mTLS works publicly. Test `/admin` without a certificate (401), then with the existing administrator certificate (200). Other hostnames should continue using their HTTP routers.

Traefik documentation: [TCP router precedence](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/routing/router/) and [TLS passthrough](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/tls/).

## Renewal behavior

The cron job checks every five minutes. It validates the source before replacing either exported file, writes files using atomic renames, and locks the export directory to serialize runs. Wardstone loads server certificates at startup, so the exporter restarts only an already-running container whose loaded public certificate differs from the validated export. It retries an unsuccessful prior reload without storing extra persistent state. It never starts a stopped container. An unchanged, matching certificate causes no restart or routine log output.

The original wildcard renewal remains Pangolin's responsibility. The exporter does not issue certificates, change Pangolin mTLS, or read/write Wardstone's database or client CA. If Pangolin changes its ACME storage format, resolver name, hostname, backend port, or container name, update the script's arguments and cron configuration accordingly.

## Rollback

Restore the timestamped Traefik dynamic-file backup first to return the hostname to its previous HTTP proxy route. Remove `/etc/cron.d/wardstone-tls` to stop scheduled exports. If needed, restore the previous CBA Compose file and recreate only Wardstone; restore the same change in its source repository through a PR so a later deployment does not reapply it. Keep the database and bootstrap directory intact. The previous HTTP proxy path will again lack client-certificate authentication until passthrough is restored.

Keep the restricted TLS export files until rollback is verified. Removing them while the new Compose mount remains configured will prevent Wardstone from starting.
