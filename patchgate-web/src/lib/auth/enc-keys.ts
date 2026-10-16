import "server-only";
import { env, type Env } from "@/lib/env";
import type { EncKeyring } from "./secret-box";

/** The AUTH_ENC_KEY keyring (webhook URLs at rest) from the environment: AUTH_ENC_KEY (current) + optional AUTH_ENC_KEY_PREVIOUS. */
export function authKeyring(e: Pick<Env, "AUTH_ENC_KEY" | "AUTH_ENC_KEY_PREVIOUS"> = env()): EncKeyring {
  if (!e.AUTH_ENC_KEY) throw new Error("AUTH_ENC_KEY is not configured");
  return { current: e.AUTH_ENC_KEY, previous: e.AUTH_ENC_KEY_PREVIOUS ?? null };
}

/** Same keyring, or null when AUTH_ENC_KEY is not configured (e.g. AUTH_MODE=oidc without local accounts). */
export function optionalAuthKeyring(e: Pick<Env, "AUTH_ENC_KEY" | "AUTH_ENC_KEY_PREVIOUS"> = env()): EncKeyring | null {
  return e.AUTH_ENC_KEY ? authKeyring(e) : null;
}
