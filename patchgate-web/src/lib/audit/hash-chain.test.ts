import { describe, expect, it } from "vitest";
import { GENESIS_HASH, computeHash, verifyChain, type ChainEntry } from "./hash-chain";

const KEY = "test-audit-key-0123456789abcdef0123";

function build(events: Omit<ChainEntry, "prevHash" | "hash">[], key = KEY): ChainEntry[] {
  const out: ChainEntry[] = [];
  let prev = GENESIS_HASH;
  for (const e of events) {
    const hash = computeHash({ ...e, prevHash: prev }, key);
    out.push({ ...e, prevHash: prev, hash });
    prev = hash;
  }
  return out;
}

const base = {
  ts: "2026-10-14T10:00:00.000Z",
  actor: "u1",
  action: "change_request.approve",
  entity: "ChangeRequest",
  entityId: "cr1",
  payload: { b: 2, a: 1 },
};
const three = () =>
  build([base, { ...base, entityId: "cr2" }, { ...base, entityId: "cr3" }]);

describe("audit hash chain", () => {
  it("is deterministic regardless of payload key order", () => {
    const h1 = computeHash({ ...base, prevHash: GENESIS_HASH }, KEY);
    const h2 = computeHash({ ...base, payload: { a: 1, b: 2 }, prevHash: GENESIS_HASH }, KEY);
    expect(h1).toBe(h2);
    expect(h1).toMatch(/^[0-9a-f]{64}$/);
  });

  it("verifies an intact chain and returns its head", () => {
    const chain = three();
    expect(verifyChain(chain, KEY)).toEqual({ valid: true, head: chain[2].hash });
  });

  it("detects a tampered field", () => {
    const tampered = three().map((e, i) => (i === 0 ? { ...e, actor: "attacker" } : e));
    expect(verifyChain(tampered, KEY)).toEqual({ valid: false, brokenAt: 0 });
  });

  it("detects a deleted middle event", () => {
    const c = three();
    expect(verifyChain([c[0], c[2]], KEY)).toEqual({ valid: false, brokenAt: 1 });
  });

  it("detects deletion of the oldest events (head truncation)", () => {
    const c = three();
    expect(verifyChain([c[1], c[2]], KEY)).toEqual({ valid: false, brokenAt: 0 });
  });

  it("rejects a chain re-forged without the secret key", () => {
    const forged = build([base, { ...base, entityId: "cr2" }], "attacker-guessed-key-xxxxxxxxxxxx");
    expect(verifyChain(forged, KEY).valid).toBe(false);
  });

  it("supports batched verification", () => {
    const c = three();
    const first = verifyChain(c.slice(0, 2), KEY);
    expect(first.valid).toBe(true);
    if (!first.valid) return;
    expect(verifyChain(c.slice(2), KEY, first.head, 2)).toEqual({ valid: true, head: c[2].hash });
  });
});

describe("audit hash chain per bank", () => {
  it("hashes platform events exactly as before multi-tenancy (null tenant is not hashed)", () => {
    const legacy = computeHash({ ...base, prevHash: GENESIS_HASH }, KEY);
    expect(computeHash({ ...base, tenantId: null, prevHash: GENESIS_HASH }, KEY)).toBe(legacy);
  });

  it("binds a bank event to its bank: the same event under another bank fails verification", () => {
    const bankA = build([{ ...base, tenantId: "bank-a" }]);
    expect(verifyChain(bankA, KEY).valid).toBe(true);
    expect(bankA[0].hash).not.toBe(computeHash({ ...base, prevHash: GENESIS_HASH }, KEY));
    const moved = bankA.map((e) => ({ ...e, tenantId: "bank-b" }));
    expect(verifyChain(moved, KEY)).toEqual({ valid: false, brokenAt: 0 });
  });
});
