import { isCritical, type NotificationEvent } from "./events";

/**
 * Recipient resolution (pure). Who an event reaches is decided when the outbox row is written:
 *  - audience groups by role (bank users of the event's bank / platform staff) plus named users
 *    (the maker, the affected account), minus excluded users (e.g. the maker of a request to approve);
 *  - inactive accounts and logins that are not e-mail addresses are skipped;
 *  - non-critical events respect the scope switch (bank / platform settings) and the personal opt-out;
 *    critical events (audit/SIEM integrity, account security) are always delivered.
 */

export type Role = "VIEWER" | "OPERATOR" | "APPROVER" | "ADMIN";

export interface CandidateUser {
  id: string;
  upn: string;
  role: Role;
  /** null = platform staff */
  tenantId: string | null;
  active: boolean;
}

export interface AudienceSpec {
  /** Users of the event's bank with one of these roles */
  bankRoles?: readonly Role[];
  /** Platform staff with one of these roles */
  platformRoles?: readonly Role[];
  /** Specific users (maker, affected account) — wherever they belong */
  userIds?: readonly string[];
  excludeUserIds?: readonly string[];
  /** Which scopes' webhooks get the event */
  webhooks: { bank: boolean; platform: boolean };
}

export interface ResolutionInput {
  event: NotificationEvent;
  tenantId: string | null;
  spec: AudienceSpec;
  users: readonly CandidateUser[];
  /** "<userId>:<event>" */
  optOuts: ReadonlySet<string>;
  bankDisabled: ReadonlySet<string>;
  platformDisabled: ReadonlySet<string>;
}

export interface EmailRecipient {
  userId: string;
  address: string;
}

export interface Resolution {
  emails: EmailRecipient[];
  webhookScopes: ("bank" | "platform")[];
}

const EMAIL_RE = /^[^\s@<>()",;:\\[\]]+@[^\s@<>()",;:\\[\]]+\.[^\s@<>()",;:\\[\]]{2,}$/;

export function isEmailAddress(v: string): boolean {
  return v.length <= 254 && EMAIL_RE.test(v);
}

export function optOutKey(userId: string, event: string): string {
  return `${userId}:${event}`;
}

/** Users the audience spec selects (before settings / opt-outs). */
export function selectAudience(spec: AudienceSpec, tenantId: string | null, users: readonly CandidateUser[]): CandidateUser[] {
  const named = new Set(spec.userIds ?? []);
  const excluded = new Set(spec.excludeUserIds ?? []);
  return users.filter((u) => {
    if (excluded.has(u.id)) return false;
    if (named.has(u.id)) return true;
    if (u.tenantId === null) return (spec.platformRoles ?? []).includes(u.role);
    return tenantId !== null && u.tenantId === tenantId && (spec.bankRoles ?? []).includes(u.role);
  });
}

export function resolveRecipients(input: ResolutionInput): Resolution {
  const { event, spec } = input;
  const critical = isCritical(event);
  const seen = new Set<string>();
  const emails: EmailRecipient[] = [];
  for (const u of selectAudience(spec, input.tenantId, input.users)) {
    if (!u.active) continue;
    const address = u.upn.trim().toLowerCase();
    if (!isEmailAddress(address) || seen.has(address)) continue;
    if (!critical) {
      if (input.optOuts.has(optOutKey(u.id, event))) continue;
      const disabled = u.tenantId === null ? input.platformDisabled : input.bankDisabled;
      if (disabled.has(event)) continue;
    }
    seen.add(address);
    emails.push({ userId: u.id, address });
  }
  const webhookScopes: ("bank" | "platform")[] = [];
  if (spec.webhooks.bank && input.tenantId !== null && (critical || !input.bankDisabled.has(event))) webhookScopes.push("bank");
  if (spec.webhooks.platform && (critical || !input.platformDisabled.has(event))) webhookScopes.push("platform");
  return { emails, webhookScopes };
}
