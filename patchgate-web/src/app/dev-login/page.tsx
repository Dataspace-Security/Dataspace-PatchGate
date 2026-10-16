import { notFound } from "next/navigation";
import { connection } from "next/server";
import { Suspense } from "react";
import { prisma } from "@/lib/db";
import { authMode, env } from "@/lib/env";
import { Alert, Card, Loading, PageHeader } from "@/components/ui";
import { DevLoginButton } from "./dev-login-button";

/** DEVELOPMENT ONLY (AUTH_MODE=dev) — switch acting user to exercise maker-checker. 404 otherwise. */
async function Users() {
  await connection();
  if (env().NODE_ENV !== "development" || authMode() !== "dev") notFound();
  const users = await prisma.user.findMany({
    where: { active: true },
    orderBy: [{ tenantId: { sort: "asc", nulls: "first" } }, { role: "asc" }],
    include: { tenant: { select: { name: true } } },
  });
  return (
    <Card title="Act as" padded={false}>
      <ul className="divide-y divide-border">
        {users.map((u) => (
          <li key={u.id} className="flex items-center justify-between gap-4 px-5 py-3 text-sm">
            <span>
              <span className="font-medium text-fg">{u.name}</span>
              <span className="ml-2 rounded-full bg-neutral-soft px-2 py-0.5 text-xs capitalize text-muted">{u.role.toLowerCase()}</span>
              <span className="ml-2 font-mono text-xs text-muted">{u.upn}</span>
              <span className="ml-2 text-xs text-muted">{u.tenant?.name ?? "PatchGate staff"}</span>
            </span>
            <DevLoginButton upn={u.upn} />
          </li>
        ))}
      </ul>
    </Card>
  );
}

export default function DevLoginPage() {
  return (
    <div className="max-w-2xl">
      <PageHeader title="Dev login" description="Switch the acting user to try the maker → checker flow." />
      <div className="mb-4">
        <Alert tone="warn">Development only (AUTH_MODE=dev). Production uses PatchGate accounts (password + authenticator) or bank SSO; this page does not exist there.</Alert>
      </div>
      <Suspense fallback={<Loading />}>
        <Users />
      </Suspense>
    </div>
  );
}
