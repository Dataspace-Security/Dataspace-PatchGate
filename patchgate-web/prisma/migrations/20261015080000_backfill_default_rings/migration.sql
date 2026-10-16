-- Banks created before default rings existed have no rollout rings and cannot open change requests.
-- Give every bank WITHOUT any ring the standard three (Test → Pilot → Production). Banks that already
-- configured rings are untouched. Ring has FORCED row-level security: run in the platform scope.
SELECT set_config('app.scope', 'platform', true);

INSERT INTO "Ring" ("id", "tenantId", "name", "wsusGroup", "order")
SELECT 'ring_' || replace(gen_random_uuid()::text, '-', ''), t."id", r.name, r.name, r.ord
FROM "Tenant" t
CROSS JOIN (VALUES ('Ring0-Test', 0), ('Ring1-Pilot', 1), ('Ring2-Prod', 2)) AS r(name, ord)
WHERE NOT EXISTS (SELECT 1 FROM "Ring" x WHERE x."tenantId" = t."id");
