import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

/**
 * Lab accounts (lab/patchgate/lab-users.json, gitignored, written by lab/patchgate/users.sh).
 * Local sign-in is password-only, so a user is just a password, a role and a bank.
 */
const USERS_FILE = join(__dirname, "..", "..", "lab", "patchgate", "lab-users.json");

export interface LabUser {
  password: string;
  role: string;
  tenant: string | null;
}

interface UsersFile {
  users: Record<string, LabUser>;
}

function readUsers(): UsersFile {
  if (!existsSync(USERS_FILE)) throw new Error(`missing ${USERS_FILE} — run lab/up-all.sh first`);
  return JSON.parse(readFileSync(USERS_FILE, "utf8")) as UsersFile;
}

export function labUser(upn: string): LabUser {
  const u = readUsers().users[upn];
  if (!u) throw new Error(`unknown lab user ${upn}`);
  return u;
}
