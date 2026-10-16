/** Browser helper for the /api/settings JSON envelope (adds DELETE to what components/api-client offers). */

export type SendResult<T> = { ok: true; data: T } | { ok: false; error: string };

export async function send<T = unknown>(url: string, method: "POST" | "PATCH" | "PUT" | "DELETE", body?: unknown): Promise<SendResult<T>> {
  try {
    const res = await fetch(url, {
      method,
      headers: body === undefined ? undefined : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
    const json = (await res.json().catch(() => null)) as { success?: boolean; data?: T; error?: string } | null;
    if (!res.ok || !json?.success) return { ok: false, error: json?.error ?? `Request failed (${res.status})` };
    return { ok: true, data: json.data as T };
  } catch {
    return { ok: false, error: "Network error — is PatchGate reachable?" };
  }
}
