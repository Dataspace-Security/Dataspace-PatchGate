# One-line site install from PatchGate ("Connectors → Add site")

Goal: bank IT installs a whole site (Tactical + connector) with ONE command on a fresh Linux VM that may reach
only our PatchGate domain (outbound 443). No USB stick needed.

```bash
curl -fsSL https://patchgate.example.com/install/site.sh | sudo bash -s -- \
  --code 7Q2M-K9XD-4HPA-ZT3W-8NBC --fingerprint 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
# VM with internet: add --online (downloads the small "-online" bundle; public images pulled by digest)
```

The installer then asks only for the site name, internal domain and TLS choice (or pass `--site-name`,
`--domain`, `--tls`). The PatchGate URL is filled in by the server (see `__PATCHGATE_URL__` below).

## What the shell side does (implemented in `install-site.sh`)

1. `site.sh` is `install-site.sh` itself. Piped into bash it has no bundle next to it, so it switches to
   download mode with `FROM_URL` = the URL the server baked in.
2. It writes the enrolment code into a 0600 temp file and sends it as a request header
   (`curl -H @file`): never in a URL, the process list or the log.
3. `GET /install/bundle/<version>/SHA256SUMS` (default version `latest`), optional `SHA256SUMS.sig`.
4. Picks `patchgate-site-<v>.tar.gz` (or `patchgate-site-<v>-online.tar.gz` with `--online`) from that list and
   downloads it with resume (`curl -C -`, 5 retries) into `/opt/patchgate-site/downloads/`.
5. Verifies the Ed25519 signature of `SHA256SUMS` with the key the server baked in (`PATCHGATE_SITE_BUNDLE_PUBKEY`,
   from server config — not the bundle volume; `--bundle-key` overrides) and refuses the bundle if the key or the
   signature is missing or wrong (`--allow-unsigned`: lab only). Then the archive against `SHA256SUMS`, extracts
   it, verifies every file against the bundle's inner `SHA256SUMS`, then re-executes the bundle's own
   `install-site.sh` (so script and bundle versions always match). Code and fingerprint are handed over in the
   environment, not argv. The same code is then used for `patchgate-connector init`.

## Server endpoints to add (patchgate-web)

All under the public origin, routed by nginx to the app (add `location ^~ /install/` to
`deploy/nginx/templates/patchgate.conf.template` with the **connector allow-list** check
`if ($connector_ip_allowed = 0) { return 403; }`, `limit_req zone=pg_connector`, `proxy_buffering off`,
`proxy_read_timeout 600s` for the bundle download).

| Method + path | Auth | Response |
|---|---|---|
| `GET /install/site.sh` | none (public; the script holds no secret) | `text/x-shellscript`: the current bundle's `install-site.sh` with the literal `__PATCHGATE_URL__` replaced by `connectorServerUrl()` (PUBLIC_BASE_URL origin). `Cache-Control: no-store`. |
| `GET /install/bundle/<version>/SHA256SUMS` | header `Authorization: PatchGate-Enrolment <code>` | `text/plain`, the outer SHA256SUMS produced by `build-site-bundle.sh` (lists `patchgate-site-<v>.tar.gz` and `patchgate-site-<v>-online.tar.gz`). |
| `GET /install/bundle/<version>/SHA256SUMS.sig` | same | the detached Ed25519 signature, or 404 if the bundle is unsigned. |
| `GET /install/bundle/<version>/<file>` | same | `application/gzip` stream of the archive, `Content-Length`, **`Range`/206 support** (resume), `Accept-Ranges: bytes`. `<file>` must be one of the two names in that version's SHA256SUMS (strict allow-list, no path segments). |

Rules for the code check (shared helper):
- `<version>`: `latest` → the platform's current site bundle; otherwise `^[A-Za-z0-9._-]{1,40}$` and must exist.
  Return `302` from `latest` to the concrete version, or serve directly — the script accepts both.
- Code: look up `ConnectorEnrollment` by `enrollCodeHash(code)`; must exist, `usedAt IS NULL`,
  `expiresAt > now()`, tenant active. **Do not consume it** (enrolment consumes it later). Wrong/expired/used →
  `403` (same body for all, no oracle). Rate-limit per code hash and per source IP (e.g. 30 requests/10 min) and
  count failed codes like login failures.
- Audit (bank chain): `connector.bundle_downloaded` with tenant, site name, version, file, source IP, the code
  hash prefix (never the code).
- Storage: bundles live outside the web image, e.g. a read-only volume `site-bundles:/data/site-bundles/<version>/`
  (the outer `SHA256SUMS`, `.sig`, both archives) mounted into web-1/web-2; `PATCHGATE_SITE_BUNDLE_DIR` and
  `PATCHGATE_SITE_BUNDLE_LATEST` in env.ts. Uploading a new bundle = copy the four files + change the pointer.
- The full bundle is large (see the build output): stream with `createReadStream` + range; never buffer.

## "Connectors → Add site" (UI)

After `createEnrollmentCode()` the dialog shows, in addition to today's `initCommand`:

```
Step 1 (bank IT, on the new site VM):
  curl -fsSL https://<PUBLIC_BASE_URL host>/install/site.sh | sudo bash -s -- --code <code> --fingerprint <fingerprint>
  (VM with internet: add --online)
Confirm the fingerprint by phone: <fingerprint>   ·   code valid until <expiresAt> (single use)
Offline/USB alternative: download patchgate-site-<v>.tar.gz + SHA256SUMS (links), then
  sudo ./install-site.sh --bundle patchgate-site-<v>.tar.gz --server <url> --code <code> --fingerprint <fp>
```

Recommended (matches RUNBOOK §6.5): send the command (with the code) and the fingerprint over **two different
channels**; the fingerprint must be read back on the phone.

After the site enrols, PatchGate should enqueue `CACHE_PACKAGE` for the current VERIFIED Tactical agent build
(`MirroredRelease` TACTICAL_AGENT, both archs) for that connector, so that the PCs can take the agent from the
site cache (`Install-PatchGateAgent.ps1` falls back to the copy shipped in the bundle until then).
