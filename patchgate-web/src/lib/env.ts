import "server-only";
import { z } from "zod";
import { parseRoleMap } from "@/lib/auth/claims";

const baseSchema = z.object({
  // Fail closed: anything not explicitly "development"/"test" is treated as production.
  NODE_ENV: z.enum(["development", "test", "production"]).default("production"),
  DATABASE_URL: z.string().startsWith("postgresql://"),
  // Internal Tactical RMM API (offline network). Never an internet host.
  // Legacy direct-Tactical bank only (LEGACY_TACTICAL_TENANT_ID). Hosted banks reach Tactical via connectors.
  TACTICAL_API_URL: z.url().optional(),
  TACTICAL_API_KEY: z.string().min(20).optional(),
  TACTICAL_TIMEOUT_MS: z.coerce.number().int().positive().default(15000),
  // Fixed, signed PatchGate install script registered in Tactical (third-party deploy)
  TACTICAL_INSTALL_SCRIPT_ID: z.coerce.number().int().positive().optional(),
  // The ONE bank whose PCs the direct TACTICAL_* connection serves (legacy path until connectors replace it).
  LEGACY_TACTICAL_TENANT_ID: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/).default("tenant-default"),
  // Internal repo URL that offline PCs download packages from
  PATCH_REPO_URL: z.url().optional(), // legacy only: PCs of the direct-Tactical bank download from /repo
  // HMAC key for the audit chain — keep in a secret store, not in the DB host.
  AUDIT_HMAC_KEY: z.string().min(32),
  // Shared secret for the scheduler that calls /api/worker/tick
  WORKER_TOKEN: z.string().min(32),
  // Bearer token Prometheus sends to GET /api/metrics. Unset = the endpoint answers 404 (disabled).
  METRICS_TOKEN: z.string().min(32).optional(),
  // Shared token for the WSUS connector scripts (Export-WsusCatalog / Sync-WsusApprovals)
  WSUS_TOKEN: z.string().min(32).optional(),
  // Bank SIEM for audit export (mandatory in production): tls://siem.bank.local:6514
  SIEM_SYSLOG_URL: z.string().optional(),
  SIEM_CA_FILE: z.string().optional(), // PEM of the bank CA that signed the SIEM certificate
  SIEM_HOSTNAME: z.string().optional(), // hostname reported in syslog records
  // Fetcher / internal repository
  REPO_DIR: z.string().default("./repo-data"), // filesystem root served at /repo
  // Serve REPO_DIR publicly at /repo (no auth). Default: false in production (connectors use the signed
  // /api/connector packages endpoint), true in development/test. Lab setups with offline PCs may set "true".
  REPO_PUBLIC: z.enum(["true", "false"]).optional(),
  // Shared repository quota in GB: above it no more Windows-update files are downloaded (monitoring signal).
  REPO_MAX_GB: z.coerce.number().positive().max(1_000_000).default(500),
  QUARANTINE_HOURS: z.coerce.number().int().min(0).max(720).default(48),
  FETCH_TIMEOUT_MS: z.coerce.number().int().positive().default(600000),
  FETCH_MAX_BYTES: z.coerce.number().int().positive().default(2_147_483_648),
  GITHUB_TOKEN: z.string().optional(), // optional: raises GitHub API rate limit for manifest lookups
  CODESIGN_CA_FILE: z.string().optional(), // non-Windows hosts: CA bundle for osslsigncode verification
  // Trusted reverse proxies in front of PatchGate (rate-limit keys). Production: >= 1.
  TRUST_PROXY_HOPS: z.coerce.number().int().min(0).max(5).default(0),
  // ---- Bank SSO (OpenID Connect: Entra ID, ADFS 2016+, Keycloak). Mandatory in production. ----
  OIDC_ISSUER_URL: z.url().optional(),
  OIDC_CLIENT_ID: z.string().min(1).optional(),
  OIDC_CLIENT_SECRET: z.string().min(1).optional(), // confidential client (recommended)
  OIDC_REDIRECT_URI: z.url().optional(), // https://patchgate.bank.local/api/auth/callback
  OIDC_POST_LOGOUT_REDIRECT_URI: z.url().optional(),
  OIDC_SCOPES: z.string().default("openid profile email"),
  OIDC_ROLE_CLAIM: z.string().default("roles"), // dotted path, e.g. "realm_access.roles" (Keycloak)
  OIDC_ROLE_MAP: z.string().optional(), // "PatchGate.Admin=ADMIN; PatchGate.Auditor=AUDITOR" (only these two roles)
  OIDC_UPN_CLAIM: z.string().default("preferred_username"),
  // Which users this IdP signs in: "platform" (our team) or ONE bank's Tenant.id. Required for AUTH_MODE=oidc.
  OIDC_USER_SCOPE: z.string().regex(/^(platform|[A-Za-z0-9_-]{1,64})$/).optional(),
  SESSION_IDLE_MINUTES: z.coerce.number().int().min(1).max(240).default(15),
  SESSION_MAX_HOURS: z.coerce.number().int().min(1).max(24).default(8),
  // Dev-only identity (no SSO). Honoured only when NODE_ENV=development AND OIDC is not configured.
  DEV_USER_UPN: z.string().optional(),
  // ---- Login mode. "local" = PatchGate accounts (password + mandatory TOTP) — the production default.
  //      "oidc" = external IdP (optional). "dev" = development user switcher (development only).
  AUTH_MODE: z.enum(["local", "oidc", "dev"]).optional(),
  // Second factor of LOCAL sign-in: "required" (default — password + 6-digit TOTP) or "off" (password only;
  // stored TOTP secrets are kept, so switching back to "required" works at once). Must be "required" before
  // go-live (GO-LIVE-CHECKLIST). OIDC is unaffected (the IdP does MFA).
  AUTH_MFA: z.enum(["required", "off"]).default("required"),
  // 32-byte key (64 hex) encrypting TOTP secrets at rest (AES-256-GCM). Required for AUTH_MODE=local.
  AUTH_ENC_KEY: z.string().regex(/^[0-9a-fA-F]{64}$/, "64 hex chars").optional(),
  // Key rotation only (RUNBOOK §9.4): the OLD AUTH_ENC_KEY, decrypt-only, until the re-encryption CLI ran.
  AUTH_ENC_KEY_PREVIOUS: z.string().regex(/^[0-9a-fA-F]{64}$/, "64 hex chars").optional(),
  // ---- Connector link (banks connect OUT to us) ----
  // PEM file with PatchGate's Ed25519 job-signing private key (production: mounted secret / KMS-backed file).
  JOB_SIGNING_KEY_FILE: z.string().optional(),
  // Who signs jobs (src/lib/connector/keys.ts): "file" = JOB_SIGNING_KEY_FILE in this process (lab/dev),
  // "remote" = the internal signer service (deploy/signer, per-bank keys), "disabled" = this container
  // never signs (e.g. the fetcher) — any signing attempt fails closed.
  JOB_SIGNER: z.enum(["file", "remote", "disabled"]).default("file"),
  JOB_SIGNER_URL: z.url().optional(), // e.g. http://signer:8080 (internal-only Docker network)
  JOB_SIGNER_TOKEN_FILE: z.string().optional(), // shared bearer token for the signer (secret file)
  // Public URL connectors use (shown on enrolment), e.g. https://patchgate.example.com
  PUBLIC_BASE_URL: z.url().optional(),
  // ---- One-line site install (GET /install/site.sh, /install/bundle/<version>/<file>; installers/site/web-install.md)
  // Read-only directory with one sub-directory per site-bundle version (SHA256SUMS, .sig, both archives,
  // install-site.sh). Unset = the /install endpoints answer 404 "site bundles not configured".
  PATCHGATE_SITE_BUNDLE_DIR: z.string().min(1).max(4096).optional(),
  // Version served for "latest" (and as /install/site.sh). Unset = the first line of <DIR>/LATEST.
  PATCHGATE_SITE_BUNDLE_LATEST: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,39}$/, "bundle version: [A-Za-z0-9._-], max 40").optional(),
  // Bundle-signing public key, "ed25519:<base64 of the raw 32-byte key>" (build-site-bundle.sh writes it to
  // bundle-signing.pub.txt). Baked into /install/site.sh: the downloaded bundle must carry a valid signature
  // from it, so a tampered bundle volume is refused. Unset = sites must pass --bundle-key or --allow-unsigned.
  PATCHGATE_SITE_BUNDLE_PUBKEY: z.string().regex(/^ed25519:[A-Za-z0-9+/]{43}=$/, "ed25519:<base64 of 32 bytes>").optional(),
  // ---- Notifications (optional: unset = notifications are recorded in the outbox and skipped) ----
  // smtps://user:pass@host:465 (implicit TLS) or smtp://user:pass@host:587 (STARTTLS; required in production)
  SMTP_URL: z.string().regex(/^smtps?:\/\/[^\s]+$/, "smtp:// or smtps:// URL").optional(),
  SMTP_FROM: z.string().min(3).max(320).optional(), // e.g. "PatchGate <patchgate@example.com>"
  // Webhook hosts notifications may be POSTed to (exact names, comma-separated), e.g. "hooks.slack.com,example.webhook.office.com"
  NOTIFY_WEBHOOK_ALLOWED_HOSTS: z.string().max(4000).optional(),
});

const OIDC_REQUIRED = ["OIDC_ISSUER_URL", "OIDC_CLIENT_ID", "OIDC_REDIRECT_URI", "OIDC_ROLE_MAP"] as const;

const envSchema = baseSchema.superRefine((e, ctx) => {
  // SSO is all-or-nothing: a half-configured IdP must not silently fall back to anything.
  const oidcSet = OIDC_REQUIRED.filter((k) => e[k]);
  if (oidcSet.length > 0 || e.AUTH_MODE === "oidc") {
    for (const k of OIDC_REQUIRED) {
      if (!e[k]) ctx.addIssue({ code: "custom", path: [k], message: "required for AUTH_MODE=oidc" });
    }
    if (!e.OIDC_USER_SCOPE) ctx.addIssue({ code: "custom", path: ["OIDC_USER_SCOPE"], message: 'required for AUTH_MODE=oidc ("platform" or a bank id)' });
  }
  if (e.OIDC_ROLE_MAP) {
    try {
      parseRoleMap(e.OIDC_ROLE_MAP);
    } catch (err: unknown) {
      ctx.addIssue({ code: "custom", path: ["OIDC_ROLE_MAP"], message: err instanceof Error ? err.message : "invalid" });
    }
  }
  if (e.AUTH_MODE === "dev" && e.NODE_ENV !== "development") {
    ctx.addIssue({ code: "custom", path: ["AUTH_MODE"], message: "dev login is only allowed with NODE_ENV=development" });
  }
  const mode = e.AUTH_MODE ?? (OIDC_REQUIRED.every((k) => !!e[k]) ? "oidc" : e.NODE_ENV === "development" ? "dev" : "local");
  if (mode === "local" && !e.AUTH_ENC_KEY) {
    ctx.addIssue({ code: "custom", path: ["AUTH_ENC_KEY"], message: "required for local login (encrypts TOTP secrets)" });
  }
  if (e.AUTH_ENC_KEY_PREVIOUS && (!e.AUTH_ENC_KEY || e.AUTH_ENC_KEY_PREVIOUS.toLowerCase() === e.AUTH_ENC_KEY.toLowerCase())) {
    ctx.addIssue({ code: "custom", path: ["AUTH_ENC_KEY_PREVIOUS"], message: "must be the old key, different from AUTH_ENC_KEY (which must be set)" });
  }
  if (e.NODE_ENV === "production" && e.JOB_SIGNER === "file" && !e.JOB_SIGNING_KEY_FILE) {
    ctx.addIssue({ code: "custom", path: ["JOB_SIGNING_KEY_FILE"], message: "connector jobs must be signed in production" });
  }
  if (e.JOB_SIGNER === "remote") {
    for (const k of ["JOB_SIGNER_URL", "JOB_SIGNER_TOKEN_FILE"] as const) {
      if (!e[k]) ctx.addIssue({ code: "custom", path: [k], message: "required for JOB_SIGNER=remote" });
    }
    if (e.JOB_SIGNER_URL && !/^https?:\/\//.test(e.JOB_SIGNER_URL)) {
      ctx.addIssue({ code: "custom", path: ["JOB_SIGNER_URL"], message: "must be an http(s) URL" });
    }
  }
  if (e.NODE_ENV === "production" && !e.SIEM_SYSLOG_URL) {
    ctx.addIssue({ code: "custom", path: ["SIEM_SYSLOG_URL"], message: "audit export to SIEM is mandatory in production" });
  }
  if (e.NODE_ENV === "production" && e.TRUST_PROXY_HOPS < 1) {
    ctx.addIssue({ code: "custom", path: ["TRUST_PROXY_HOPS"], message: "run behind the bank reverse proxy and set >= 1 (per-client rate limits)" });
  }
  if (e.NODE_ENV !== "production") return; // dev/test may use plain tcp/http to local fakes
  if (e.SIEM_SYSLOG_URL && !e.SIEM_SYSLOG_URL.startsWith("tls://")) {
    ctx.addIssue({ code: "custom", path: ["SIEM_SYSLOG_URL"], message: "must use tls:// outside development" });
  }
  for (const key of ["TACTICAL_API_URL", "PATCH_REPO_URL", "OIDC_ISSUER_URL", "OIDC_REDIRECT_URI"] as const) {
    if (e[key] && !e[key].startsWith("https://")) {
      ctx.addIssue({ code: "custom", path: [key], message: "must use https outside development" });
    }
  }
});

export type Env = z.infer<typeof baseSchema>;

/** Effective login mode: explicit AUTH_MODE, else oidc if configured, else dev in development, else local. */
export function authMode(e: Env = env()): "local" | "oidc" | "dev" {
  if (e.AUTH_MODE) return e.AUTH_MODE;
  if (OIDC_REQUIRED.every((k) => !!e[k])) return "oidc";
  return e.NODE_ENV === "development" ? "dev" : "local";
}

/** Does local sign-in ask for the 6-digit TOTP code? (AUTH_MFA=off → password only; OIDC/dev: not applicable.) */
export function mfaRequired(e: Pick<Env, "AUTH_MFA"> = env()): boolean {
  return e.AUTH_MFA !== "off";
}

/** Local sign-in with the second factor switched off — warned about on /operations, /api/health and to admins. */
export function mfaDisabled(e: Env = env()): boolean {
  return authMode(e) === "local" && !mfaRequired(e);
}

/** Is the /repo tree served without authentication? Explicit REPO_PUBLIC, else only outside production. */
export function repoPublic(e: Pick<Env, "REPO_PUBLIC" | "NODE_ENV"> = env()): boolean {
  return e.REPO_PUBLIC ? e.REPO_PUBLIC === "true" : e.NODE_ENV !== "production";
}

/** True when bank SSO is configured (then the dev identity is never honoured, even in development). */
export function oidcEnabled(e: Env = env()): boolean {
  return OIDC_REQUIRED.every((k) => !!e[k]);
}

let cached: Env | undefined;

export function env(): Env {
  if (!cached) {
    const parsed = envSchema.safeParse(process.env);
    if (!parsed.success) {
      const fields = parsed.error.issues.map((i) => i.path.join(".")).join(", ");
      throw new Error(`Invalid PatchGate configuration: ${fields}`);
    }
    cached = parsed.data;
  }
  return cached;
}
