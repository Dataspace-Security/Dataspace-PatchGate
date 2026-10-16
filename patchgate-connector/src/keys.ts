import { generateKeyPairSync, createPublicKey, type KeyObject } from "node:crypto";
import { readFile, stat } from "node:fs/promises";
import { privateKeyFromPem } from "./protocol.ts";
import { writeFileAtomic } from "./util/fsx.ts";

/** The connector's Ed25519 identity key. Generated locally; the private key never leaves the bank. */

export interface ConnectorKeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
  privatePem: string;
}

export function generateConnectorKey(): ConnectorKeyPair {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privatePem = privateKey.export({ format: "pem", type: "pkcs8" }).toString();
  return { privateKey, publicKey, privatePem };
}

/** Write the private key with mode 0600 (owner read/write only). */
export async function savePrivateKey(path: string, pem: string): Promise<void> {
  await writeFileAtomic(path, pem, 0o600);
}

export async function loadPrivateKey(path: string): Promise<KeyObject> {
  let pem: string;
  try {
    pem = await readFile(path, "utf8");
  } catch (err) {
    throw new Error(`cannot read connector private key: ${(err as NodeJS.ErrnoException).code ?? "error"}`);
  }
  return privateKeyFromPem(pem);
}

export function publicFromPrivate(privateKey: KeyObject): KeyObject {
  return createPublicKey(privateKey);
}

/** On POSIX, warn if group/other can read the key file. */
export async function keyFileTooOpen(path: string): Promise<boolean> {
  if (process.platform === "win32") return false;
  const st = await stat(path);
  return (st.mode & 0o077) !== 0;
}
