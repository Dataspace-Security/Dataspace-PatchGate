"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { callApi } from "@/components/api-client";
import { BUTTON, buttonBase } from "@/components/ui";

export function DevLoginButton({ upn }: { upn: string }) {
  const router = useRouter();
  const [error, setError] = useState<string | null>(null);

  async function login() {
    const r = await callApi("/api/dev-login", "POST", { upn });
    if (!r.ok) return setError(r.error);
    router.push("/");
    router.refresh();
  }

  return (
    <span>
      <button type="button" onClick={login} className={`${buttonBase} ${BUTTON.default}`}>
        Use this user
      </button>
      {error && <span className="ml-2 text-xs text-danger">{error}</span>}
    </span>
  );
}
