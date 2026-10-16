import { z } from "zod";

/**
 * Shapes returned by Tactical RMM's REST API (verified against tacticalrmm source).
 * Adapted from patchgate-web/src/lib/tactical/types.ts.
 */

export const winUpdateSchema = z.object({
  id: z.number().int(),
  guid: z.string(),
  kb: z.string().nullable(),
  title: z.string().nullable(),
  installed: z.boolean(),
  action: z.enum(["inherit", "approve", "ignore", "nothing"]),
  severity: z.string().nullable(),
});
export type TacticalWinUpdate = z.infer<typeof winUpdateSchema>;
export type WinUpdateAction = TacticalWinUpdate["action"];

export const agentSchema = z.object({
  agent_id: z.string(),
  version: z.string().nullish(),
  goarch: z.string().nullish(),
  hostname: z.string(),
  client_name: z.string().nullish(),
  site_name: z.string().nullish(),
  plat: z.string(),
  operating_system: z.string().nullish(),
  status: z.string().nullish(),
  // Not validated strictly (a surprising type must never fail the whole agent list): narrowed in syncAgents.
  last_seen: z.unknown().optional(),
  boot_time: z.unknown().optional(),
  // GET /agents/ annotates Exists(WinUpdate action="approve", installed=False) per agent (tacticalrmm 1.5.x
  // agents/views.py GetAgents + AgentTableSerializer): lets the approval guard read only those agents' updates.
  has_patches_pending: z.boolean().nullish(),
});
export type TacticalAgent = z.infer<typeof agentSchema>;

export const softwareItemSchema = z
  .object({
    name: z.string(),
    version: z.string().default(""),
    publisher: z.string().nullish(),
    uninstall: z.string().nullish(),
  })
  .loose();
export type SoftwareItem = z.infer<typeof softwareItemSchema>;

// GET /software/{agent}/ returns either [] or { software: [...] }
export const agentSoftwareSchema = z.union([
  z.array(z.never()).transform((): SoftwareItem[] => []),
  z.object({ software: z.array(softwareItemSchema) }).transform((v) => v.software),
]);

/** GET /agents/{agent_id}/ — only what the connector needs. */
export const agentDetailSchema = z.object({ version: z.string(), goarch: z.string().nullish() }).loose();
export type TacticalAgentDetail = z.infer<typeof agentDetailSchema>;

/**
 * One entry of Tactical's audit log: PATCH /logs/audit/ → { audit_logs: [...], total } (tacticalrmm 1.5.x
 * logs/views.py GetAuditLogs + AuditLogSerializer, fields "__all__"; permission can_view_auditlogs).
 * entry_time is the DateTimeField as DRF renders it (ISO 8601); ip_address is omitted when debug_info is empty.
 */
export const auditLogSchema = z
  .object({
    id: z.number().int(),
    username: z.string(),
    agent: z.string().nullish(),
    agent_id: z.string().nullish(),
    entry_time: z.string(),
    action: z.string(),
    object_type: z.string(),
    message: z.string().nullish(),
    ip_address: z.string().nullish(),
    // Full object snapshots (may contain Tactical secrets, e.g. SMTP password): only single booleans are ever
    // read from them (agent auto-update), they are never forwarded.
    before_value: z.unknown().optional(),
    after_value: z.unknown().optional(),
  })
  .loose();
export type TacticalAuditLog = z.infer<typeof auditLogSchema>;

export const auditLogPageSchema = z.object({ audit_logs: z.array(auditLogSchema), total: z.number().int().min(0) }).loose();
export type TacticalAuditLogPage = z.infer<typeof auditLogPageSchema>;
