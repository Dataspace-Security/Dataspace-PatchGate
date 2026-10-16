import { connection } from "next/server";
import { siteScriptResponse } from "@/lib/connector/bundle-http";

/**
 * GET /install/site.sh — the current site bundle's install-site.sh with the PatchGate URL baked in
 * (`curl -fsSL https://<host>/install/site.sh | sudo bash -s -- --code … --fingerprint …`).
 * Public (the script holds no secret); nginx limits it to the connector allow-list. installers/site/web-install.md
 */
export async function GET(): Promise<Response> {
  await connection();
  return siteScriptResponse();
}
