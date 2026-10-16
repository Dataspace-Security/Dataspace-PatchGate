import { encryptSecret, needsReencryption, openSecret, type EncKeyring } from "@/lib/auth/secret-box";

/**
 * Webhook URLs at rest (they embed a secret token): sealed with AUTH_ENC_KEY (AES-256-GCM, key id, previous-key
 * decrypt — src/lib/auth/secret-box.ts), the same keyring and rotation CLI as the TOTP secrets.
 *  - NotificationSetting.webhookUrlsEnc: one box per URL, bound to the setting scope (AAD), so a box copied into
 *    another bank's settings does not decrypt.
 *  - Notification.target (channel WEBHOOK): the outbox copy, sealed as well.
 * Pre-encryption plaintext (NotificationSetting.webhookUrlsLegacy, old outbox rows) keeps working and is drained
 * by drainLegacyWebhooks (worker tick), the next settings change and the rotation CLI.
 * Pure (no env, no DB): callers pass the keyring (enc-keys.ts → webhookKeyring()).
 */

const settingAad = (scope: string) => `notification-setting:${scope}:webhook-url`;
export const OUTBOX_WEBHOOK_AAD = "notification-outbox:webhook-url";

/** A stored value that is still plaintext (legacy): http(s) URLs contain ':', sealed boxes never do. */
export const isPlainUrl = (v: string): boolean => v.includes(":");

export function sealSettingUrl(url: string, scope: string, ring: EncKeyring): string {
  return encryptSecret(Buffer.from(url, "utf8"), ring.current, settingAad(scope));
}

export function sealOutboxTarget(url: string, ring: EncKeyring): string {
  return encryptSecret(Buffer.from(url, "utf8"), ring.current, OUTBOX_WEBHOOK_AAD);
}

export interface OpenedUrl {
  url: string;
  /** must be rewritten (legacy plaintext, previous key or old box format) */
  stale: boolean;
}

function openWith(box: string, aad: string, ring: EncKeyring | null): OpenedUrl {
  if (isPlainUrl(box)) return { url: box, stale: true };
  if (!ring) throw new Error("AUTH_ENC_KEY is not configured: encrypted webhook URL cannot be read");
  const o = openSecret(box, ring, aad);
  return { url: o.plain.toString("utf8"), stale: needsReencryption(o) };
}

export const openSettingUrl = (box: string, scope: string, ring: EncKeyring | null): OpenedUrl => openWith(box, settingAad(scope), ring);
export const openOutboxTarget = (target: string, ring: EncKeyring | null): OpenedUrl => openWith(target, OUTBOX_WEBHOOK_AAD, ring);

export interface SettingWebhookColumns {
  scope: string;
  webhookUrlsEnc: string[];
  webhookUrlsLegacy: string[];
}

export interface SettingUrls {
  /** decrypted URLs (sealed first, then legacy), de-duplicated, in stored order */
  urls: string[];
  /** boxes that could not be decrypted (unknown key / tampered): never shown, never dropped silently */
  undecryptable: string[];
  /** true when the row must be rewritten (legacy plaintext or boxes under the previous key / old format) */
  stale: boolean;
}

/** All webhook URLs of one settings row. */
export function readSettingUrls(row: SettingWebhookColumns, ring: EncKeyring | null): SettingUrls {
  const urls: string[] = [];
  const undecryptable: string[] = [];
  let stale = row.webhookUrlsLegacy.length > 0;
  for (const box of row.webhookUrlsEnc) {
    try {
      const o = openSettingUrl(box, row.scope, ring);
      stale ||= o.stale;
      if (!urls.includes(o.url)) urls.push(o.url);
    } catch {
      undecryptable.push(box);
    }
  }
  for (const u of row.webhookUrlsLegacy) if (isPlainUrl(u) && !urls.includes(u)) urls.push(u);
  return { urls, undecryptable, stale };
}

/** Columns to store `urls` sealed under the CURRENT key (undecryptable boxes are kept as they are). */
export function sealedColumns(scope: string, urls: readonly string[], undecryptable: readonly string[], ring: EncKeyring): { webhookUrlsEnc: string[]; webhookUrlsLegacy: string[] } {
  return { webhookUrlsEnc: [...urls.map((u) => sealSettingUrl(u, scope, ring)), ...undecryptable], webhookUrlsLegacy: [] };
}
