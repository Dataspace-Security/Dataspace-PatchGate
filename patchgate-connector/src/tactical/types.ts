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
