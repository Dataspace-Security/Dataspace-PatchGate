import { createCipheriv, createDecipheriv, createHmac, randomBytes } from "node:crypto";

/**
 * AES-256-GCM for small secrets at rest (notification webhook URLs) with AUTH_ENC_KEY (32 bytes, hex).
 *
 * Formats (base64url parts, "." separated):
 *  - "v1.<iv>.<tag>.<ct>.<kid>" (current): kid = 8-hex key id (HMAC of a fixed label under the key — reveals
 *    nothing about the key). The kid is bound into the AAD, so it cannot be stripped or swapped.
 *  - "v1.<iv>.<tag>.<ct>" (legacy, before key ids): still decrypted; the key is found by trial (GCM
 *    authenticates, so a wrong key always fails). The rotation CLI rewrites these in the current format.
 * `aad` binds the ciphertext to its owner (e.g. the settings scope): a box copied onto another row won't decrypt.
 *
 * Rotation: encrypt ALWAYS with the current key; decrypt with the current or the previous key
 * (AUTH_ENC_KEY_PREVIOUS) — see openSecret / RUNBOOK §9.4.
 */

const VERSION = "v1";
const IV_LEN = 12;
const TAG_LEN = 16;
const KID_RE = /^[0-9a-f]{8}$/;

function keyFrom(hex: string): Buffer {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("AUTH_ENC_KEY must be 64 hex characters");
  return Buffer.from(hex, "hex");
}

/** Short, non-secret identifier of a key (shown in counts/audit, embedded in ciphertexts). */
export function keyId(keyHex: string): string {
  return createHmac("sha256", keyFrom(keyHex)).update("patchgate.auth-enc-key.id.v1").digest("hex").slice(0, 8);
}

const aadFor = (owner: string, kid: string | null) => Buffer.from(kid ? `${owner}\u0000kid:${kid}` : owner, "utf8");

interface ParsedBox {
  iv: Buffer;
  tag: Buffer;
  ct: Buffer;
  kid: string | null;
}

function parseBox(box: string): ParsedBox {
  const parts = box.split(".");
  if ((parts.length !== 4 && parts.length !== 5) || parts[0] !== VERSION) throw new Error("Unsupported secret format");
  const kid = parts.length === 5 ? parts[4] : null;
  if (kid !== null && !KID_RE.test(kid)) throw new Error("Malformed secret");
  const iv = Buffer.from(parts[1], "base64url");
  const tag = Buffer.from(parts[2], "base64url");
  const ct = Buffer.from(parts[3], "base64url");
  if (iv.length !== IV_LEN || tag.length !== TAG_LEN) throw new Error("Malformed secret");
  return { iv, tag, ct, kid };
}

function decryptWith(p: ParsedBox, keyHex: string, owner: string): Buffer {
  const decipher = createDecipheriv("aes-256-gcm", keyFrom(keyHex), p.iv, { authTagLength: TAG_LEN });
  decipher.setAAD(aadFor(owner, p.kid));
  decipher.setAuthTag(p.tag);
  return Buffer.concat([decipher.update(p.ct), decipher.final()]);
}

/** Encrypt with `keyHex` (always the CURRENT key); the output names the key by its id. */
export function encryptSecret(plain: Uint8Array, keyHex: string, aad: string): string {
  const kid = keyId(keyHex);
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv("aes-256-gcm", keyFrom(keyHex), iv, { authTagLength: TAG_LEN });
  cipher.setAAD(aadFor(aad, kid));
  const ct = Buffer.concat([cipher.update(plain), cipher.final()]);
  return [VERSION, iv.toString("base64url"), cipher.getAuthTag().toString("base64url"), ct.toString("base64url"), kid].join(".");
}

/** Single-key decrypt. Throws if the ciphertext was modified, the key is wrong, or it belongs to another owner. */
export function decryptSecret(box: string, keyHex: string, aad: string): Buffer {
  const p = parseBox(box);
  if (p.kid !== null && p.kid !== keyId(keyHex)) throw new Error("Secret was encrypted with a different key");
  return decryptWith(p, keyHex, aad);
}

/** Current key (encrypts + decrypts) and the optional previous key (decrypt-only, during a rotation). */
export interface EncKeyring {
  current: string;
  previous?: string | null;
}

export interface OpenedSecret {
  plain: Buffer;
  /** Id of the key that decrypted it. */
  keyId: string;
  /** Decrypted with the previous key → must be re-encrypted (rotation CLI). */
  usedPrevious: boolean;
  /** Legacy format without a key id → should be rewritten (rotation CLI). */
  legacy: boolean;
}

/** True when the box must be rewritten to be "current key, current format". */
export const needsReencryption = (o: OpenedSecret): boolean => o.usedPrevious || o.legacy;

/**
 * Decrypt with the keyring: a key id selects the key directly (unknown id → error); legacy boxes try the
 * current key, then the previous one. Tampering, a wrong owner or an unknown key all throw.
 */
export function openSecret(box: string, ring: EncKeyring, aad: string): OpenedSecret {
  const p = parseBox(box);
  const keys = [{ hex: ring.current, previous: false }, ...(ring.previous ? [{ hex: ring.previous, previous: true }] : [])].map((k) => ({
    ...k,
    id: keyId(k.hex),
  }));
  if (p.kid !== null) {
    const k = keys.find((x) => x.id === p.kid);
    if (!k) throw new Error(`Secret was encrypted with an unknown key (id ${p.kid})`);
    return { plain: decryptWith(p, k.hex, aad), keyId: k.id, usedPrevious: k.previous, legacy: false };
  }
  let lastErr: unknown = null;
  for (const k of keys) {
    try {
      return { plain: decryptWith(p, k.hex, aad), keyId: k.id, usedPrevious: k.previous, legacy: true };
    } catch (err: unknown) {
      lastErr = err;
    }
  }
  throw lastErr instanceof Error ? lastErr : new Error("Secret could not be decrypted");
}
