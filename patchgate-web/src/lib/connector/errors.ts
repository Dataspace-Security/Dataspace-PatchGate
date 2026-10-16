/**
 * Typed failures of the connector API. The route layer maps them to the status codes the connector
 * relies on (patchgate-connector/README "Server-side expectations"):
 *  401/403 auth · 400/422 invalid (no retry) · 404/410 unknown job (no retry) · 409 duplicate result ·
 *  413 body too large · 429/503 retry later (Retry-After).
 */
export type ConnectorErrorStatus = 400 | 401 | 403 | 404 | 409 | 410 | 413 | 422 | 429 | 503;

export class ConnectorApiError extends Error {
  constructor(
    readonly status: ConnectorErrorStatus,
    message: string,
    readonly retryAfterSec?: number,
  ) {
    super(message);
    this.name = "ConnectorApiError";
  }
}

/** Authentication failure: always the same terse public message, the reason goes to the log only. */
export class ConnectorAuthError extends ConnectorApiError {
  constructor(
    readonly reason: string,
    status: 401 | 403 = 401,
  ) {
    super(status, status === 403 ? "forbidden" : "unauthorized");
    this.name = "ConnectorAuthError";
  }
}
