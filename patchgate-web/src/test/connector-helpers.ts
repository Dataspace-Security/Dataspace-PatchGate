/**
 * Shared fixtures for src/test/connector-*.int.test.ts: a connector identity (Ed25519 key generated
 * "on the bank side"), enrolment through the real service, and signed request parts exactly as the
 * connector builds them (patchgate-connector/src/pg-client.ts).
 */
import { generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { HEADERS, enrollProofMessage, rawFromPublicKey, sha256Hex, signRequest } from "@/lib/connector/protocol";
import type { SignedRequestParts } from "@/lib/connector/auth";

export interface ConnectorKey {
  privateKey: KeyObject;
  publicRaw: string;
}

export function makeConnectorKey(): ConnectorKey {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  return { privateKey, publicRaw: rawFromPublicKey(publicKey) };
}

export function enrollBody(code: string, key: ConnectorKey, version = "1.0.0") {
  const proof = sign(null, Buffer.from(enrollProofMessage(code, key.publicRaw)), key.privateKey).toString("base64");
  return { code, publicKey: key.publicRaw, version, proof };
}

export interface SignOptions {
  timestamp?: number;
  nonce?: string;
  /** sign a different path than the one "sent" (tamper simulation) */
  signedPath?: string;
}

export function signedParts(key: ConnectorKey, connectorId: string, method: string, pathWithQuery: string, body: string | Uint8Array = "", o: SignOptions = {}): SignedRequestParts {
  const timestamp = String(o.timestamp ?? Date.now());
  const nonce = o.nonce ?? randomBytes(16).toString("base64url");
  const bytes = typeof body === "string" ? new TextEncoder().encode(body) : body;
  const headers = new Headers({
    [HEADERS.connector]: connectorId,
    [HEADERS.timestamp]: timestamp,
    [HEADERS.nonce]: nonce,
    [HEADERS.signature]: signRequest(key.privateKey, method, o.signedPath ?? pathWithQuery, timestamp, nonce, bytes),
  });
  return { method, pathWithQuery, headers, body: bytes };
}

/** Write a package file into the test repository and return its repo path, sha256 and size. */
export function writeRepoFile(repoDir: string, repoPath: string, content: string | Buffer): { repoPath: string; sha256: string; size: number } {
  const abs = join(repoDir, ...repoPath.split("/"));
  mkdirSync(dirname(abs), { recursive: true });
  const bytes = typeof content === "string" ? Buffer.from(content) : content;
  writeFileSync(abs, bytes);
  return { repoPath, sha256: sha256Hex(bytes), size: bytes.length };
}

/** A user row shaped like SessionUser. */
export function sessionUserOf(u: { id: string; role: import("@/lib/auth/roles").Role; upn: string; name: string; tenantId: string | null }) {
  return { id: u.id, role: u.role, upn: u.upn, name: u.name, tenantId: u.tenantId };
}

export const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
