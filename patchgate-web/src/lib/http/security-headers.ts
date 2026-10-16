/**
 * Security headers for every PatchGate response (set at runtime in the proxy so the IdP origin comes
 * from deployment config, not build-time config).
 *
 * CSP note: the App Router streams inline RSC payload scripts and this app uses cacheComponents
 * (prerendered shells), which Next.js documents as incompatible with nonce-based CSP — so scripts need
 * 'unsafe-inline'. Everything else is locked down: no framing, no plugins, no foreign scripts/fetches,
 * forms only to PatchGate (+ the IdP, for the sign-out redirect chain).
 */
export interface SecurityHeaderOptions {
  isDev: boolean;
  /** https origin of the bank IdP (sign-out redirect target), if SSO is configured */
  idpOrigin: string | null;
  /** send HSTS (only when served over https) */
  https: boolean;
}

export function securityHeaders(o: SecurityHeaderOptions): Record<string, string> {
  const formAction = ["'self'", ...(o.idpOrigin ? [o.idpOrigin] : [])].join(" ");
  const csp = [
    "default-src 'self'",
    `script-src 'self' 'unsafe-inline'${o.isDev ? " 'unsafe-eval'" : ""}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    `connect-src 'self'${o.isDev ? " ws: wss:" : ""}`,
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
    `form-action ${formAction}`,
    "manifest-src 'self'",
    "worker-src 'self'",
    ...(o.isDev ? [] : ["upgrade-insecure-requests"]),
  ].join("; ");

  return {
    "Content-Security-Policy": csp,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    // NOT "no-referrer": Chrome then sends `Origin: null` on form POSTs, which breaks the same-origin CSRF check.
    "Referrer-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    ...(o.https && !o.isDev ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
  };
}

/** https origin of an issuer URL, or null if absent/invalid/not https (never widen the CSP on bad input). */
export function idpOriginOf(issuer: string | undefined): string | null {
  if (!issuer) return null;
  try {
    const u = new URL(issuer);
    return u.protocol === "https:" ? u.origin : null;
  } catch {
    return null;
  }
}
