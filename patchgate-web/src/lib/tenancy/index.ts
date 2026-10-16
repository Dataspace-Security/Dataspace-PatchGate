/**
 * Tenancy layer (ARCHITECTURE-HOSTED §4). Import from here in pages / routes / services:
 *  - requireTenant / requireActiveTenant / resolveActiveTenant: which bank this request acts for
 *  - assertSameTenant / canActForTenant: object-level checks
 *  - withTenant / withPlatform: RLS-scoped DB transactions
 * Pages use getPageTenant() from "@/lib/tenancy/page" (redirects instead of throwing).
 */
export * from "./policy";
export * from "./context";
export * from "./db";
