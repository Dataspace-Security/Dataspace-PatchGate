import { createHash, randomBytes } from "node:crypto";

/** Cookie names + opaque token helpers shared by every login mode. Only SHA-256(token) is stored. */

export const SESSION_COOKIE = "__Host-pg_session"; // keep in sync with src/proxy.ts
/** Pending password-change step of local sign-in (short-lived, single use). */
export const CHALLENGE_COOKIE = "__Host-pg_challenge";

export const sha256Hex = (s: string): string => createHash("sha256").update(s).digest("hex");
export const randomToken = (): string => randomBytes(32).toString("base64url");
