import type { HoldReason } from "@prisma/client";
import { isPinnableOrg, orgMatches, signerOrgOf } from "@/lib/fetch/dn";

/**
 * What to do with a downloaded third-party installer. Pure: inputs are the facts gathered at download.
 *
 *   signature invalid/untrusted/absent ........................ reject
 *   catalog hash matches + signer org pinned .................. publish (automatic)
 *   catalog hash matches + no pins yet ........................ hold FIRST_SIGNER   (approve = pin org)
 *   catalog hash matches + valid signer not in pins ........... hold SIGNER_CHANGED (approve = add pin)
 *   catalog hash differs + signer org pinned + allowHashDrift . hold HASH_DRIFT     (approve = this exact hash)
 *   catalog hash differs otherwise ............................ reject
 */
export type SignatureFacts = { ok: true; subject: string } | { ok: false; reason: string };

export type TrustDecision =
  | { action: "publish"; signerOrg: string }
  | { action: "hold"; reason: HoldReason; signerOrg: string; detail: string }
  | { action: "reject"; reason: string };

export interface TrustInput {
  signature: SignatureFacts;
  pins: string | null;
  catalogSha256: string;
  actualSha256: string;
  allowHashDrift: boolean;
}

export function decideTrust(i: TrustInput): TrustDecision {
  const hashOk = i.catalogSha256.toLowerCase() === i.actualSha256.toLowerCase();
  if (!i.signature.ok) {
    return { action: "reject", reason: hashOk ? i.signature.reason : `sha256 mismatch and ${i.signature.reason}` };
  }
  const org = signerOrgOf(i.signature.subject);
  if (!org) return { action: "reject", reason: "certificate has no organisation (O=) to pin" };
  if (!isPinnableOrg(org)) return { action: "reject", reason: `signer organisation cannot be pinned (${org.slice(0, 80)})` };
  const pinned = i.pins !== null && orgMatches(i.signature.subject, i.pins);

  if (!hashOk) {
    if (pinned && i.allowHashDrift) {
      return {
        action: "hold",
        reason: "HASH_DRIFT",
        signerOrg: org,
        detail: `catalog ${i.catalogSha256.slice(0, 12)}…, downloaded ${i.actualSha256.slice(0, 12)}… (signed by pinned ${org})`,
      };
    }
    return { action: "reject", reason: `sha256 mismatch (manifest ${i.catalogSha256}, got ${i.actualSha256})` };
  }
  if (pinned) return { action: "publish", signerOrg: org };
  if (!i.pins) return { action: "hold", reason: "FIRST_SIGNER", signerOrg: org, detail: `first download signed by ${org}` };
  return { action: "hold", reason: "SIGNER_CHANGED", signerOrg: org, detail: `signed by ${org}, pinned: ${i.pins}` };
}
