import "server-only";
import { redirect } from "next/navigation";
import { AuthError, getCurrentUser, type SessionUser } from "./session";

/** For pages: an unauthenticated / expired visitor is sent to sign-in instead of an error page. */
export async function getPageUser(): Promise<SessionUser> {
  try {
    return await getCurrentUser();
  } catch (err: unknown) {
    if (err instanceof AuthError) {
      const reason = err.message === "Session expired" ? "expired" : err.message === "Account deactivated" ? "deactivated" : "signin";
      redirect(`/login?error=${reason}`);
    }
    throw err;
  }
}
