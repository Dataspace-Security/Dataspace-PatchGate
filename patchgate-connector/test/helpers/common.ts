import { readFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { createServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { IncomingMessage } from "node:http";

export const FIXTURES = resolve(dirname(fileURLToPath(import.meta.url)), "..", "fixtures");
export const TLS = {
  caFile: join(FIXTURES, "test-ca.pem"),
  certFile: join(FIXTURES, "localhost.pem"),
  keyFile: join(FIXTURES, "localhost.key"),
  ca: readFileSync(join(FIXTURES, "test-ca.pem")),
  cert: readFileSync(join(FIXTURES, "localhost.pem")),
  key: readFileSync(join(FIXTURES, "localhost.key")),
};

export async function tempDir(prefix = "pgc-"): Promise<{ dir: string; cleanup: () => Promise<void> }> {
  const dir = await mkdtemp(join(tmpdir(), prefix));
  return { dir, cleanup: () => rm(dir, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 }) };
}

export async function freePort(): Promise<number> {
  return new Promise((res, rej) => {
    const s = createServer();
    s.once("error", rej);
    s.listen(0, "127.0.0.1", () => {
      const port = (s.address() as AddressInfo).port;
      s.close(() => res(port));
    });
  });
}

export async function readBody(req: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
}

export async function waitFor<T>(fn: () => T | undefined | false | Promise<T | undefined | false>, timeoutMs = 10_000, stepMs = 25): Promise<T> {
  const until = Date.now() + timeoutMs;
  for (;;) {
    const v = await fn();
    if (v) return v;
    if (Date.now() > until) throw new Error("waitFor: timed out");
    await new Promise((r) => setTimeout(r, stepMs));
  }
}
