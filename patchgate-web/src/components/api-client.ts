/** Browser-side helper for PatchGate's JSON API envelope ({ success, data, error }). */

export type ApiResult<T> = { ok: true; data: T } | { ok: false; error: string };

export async function callApi<T>(url: string, method: "POST" | "PATCH" | "PUT", body?: unknown): Promise<ApiResult<T>> {
  try {
    const res = await fetch(url, {
      method,
      headers: { "Content-Type": "application/json" },
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
