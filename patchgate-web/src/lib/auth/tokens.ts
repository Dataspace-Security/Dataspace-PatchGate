import { createHash, randomBytes } from "node:crypto";

/** Cookie names + opaque token helpers shared by every login mode. Only SHA-256(token) is stored. */

export const SESSION_COOKIE = "__Host-pg_session"; // keep in sync with src/proxy.ts
export const MFA_COOKIE = "__Host-pg_mfa";

export const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");
export const randomToken = (): string => randomBytes(32).toString("base64url");
