import "server-only";
import { Prisma } from "@prisma/client";
import type { SessionUser } from "@/lib/auth/session";
import { DomainError } from "@/lib/errors";
import type { Tx } from "@/lib/tenancy";

export interface ApprovalRow {
  userId: string;
  userUpn: string;
  approverBankId: string | null;
  deployNow: boolean;
}

/**
 * Persist one approver's decision (inside the request's row lock). The unique (request, user) index and a DB
 * trigger (maker ≠ approver) back the state machine up. Returns this row + every approval of the request.
 */
export async function recordApproval(
  tx: Tx,
  tenantId: string,
  crId: string,
  user: Pick<SessionUser, "id" | "upn" | "name" | "tenantId">,
  deployNow: boolean,
): Promise<{ row: ApprovalRow; all: ApprovalRow[] }> {
  try {
    await tx.changeRequestApproval.create({
      data: { tenantId, changeRequestId: crId, userId: user.id, userUpn: user.upn, userName: user.name, approverBankId: user.tenantId, deployNow },
    });
  } catch (err: unknown) {
    if (err instanceof Prisma.PrismaClientKnownRequestError && err.code === "P2002") {
      throw new DomainError("You already approved this request; a second, different approver is required", 409);
    }
    throw err;
  }
  const all = await tx.changeRequestApproval.findMany({
    where: { changeRequestId: crId, tenantId },
    orderBy: { createdAt: "asc" },
    select: { userId: true, userUpn: true, approverBankId: true, deployNow: true },
  });
  const row = all.find((a) => a.userId === user.id)!;
  return { row, all };
}
