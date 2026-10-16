import { describe, expect, it } from "vitest";
import { orgMatches, parseDn, PUBLISHER_PIN_RE } from "./dn";

describe("parseDn", () => {
  it("parses Windows-style DNs including quoted values with commas", () => {
    expect(parseDn('CN="Foo, Inc.", O="Foo, Inc.", L=Redmond, C=US')).toEqual([
      ["CN", "Foo, Inc."],
      ["O", "Foo, Inc."],
      ["L", "Redmond"],
      ["C", "US"],
    ]);
  });
  it("parses OpenSSL slash-style DNs", () => {
    expect(parseDn("/C=US/ST=California/O=Google LLC/CN=Google LLC")).toEqual([
      ["C", "US"],
      ["ST", "California"],
      ["O", "Google LLC"],
      ["CN", "Google LLC"],
    ]);
  });
  it("parses newline-separated RDNs (X500DistinguishedName UseNewLines)", () => {
    expect(parseDn("CN=Microsoft Corporation\r\nO=Microsoft Corporation\r\nC=US")).toContainEqual(["O", "Microsoft Corporation"]);
  });
});

describe("orgMatches (exact O= pin)", () => {
  it("matches the exact organisation", () => {
    expect(orgMatches("CN=Google LLC, O=Google LLC, C=US", "O=Google LLC")).toBe(true);
    expect(orgMatches("/C=US/O=Google LLC/CN=Google LLC", "O=Google LLC")).toBe(true);
    expect(orgMatches("CN=x, O=google llc", "O=Google LLC")).toBe(true); // case-insensitive
  });
  it.each([
    ["suffix attack", "CN=x, O=Google LLC Evil"],
    ["prefix attack", "CN=x, O=Not Google LLC"],
    ["only in CN", "CN=O=Google LLC, O=Evil Corp"],
    ["quoted CN smuggling", 'CN="a,O=Google LLC", O=Evil Corp'],
    ["no O at all", "CN=Google LLC"],
  ])("rejects %s", (_n, subject) => {
    expect(orgMatches(subject, "O=Google LLC")).toBe(false);
  });
});

describe("PUBLISHER_PIN_RE", () => {
  it("requires a single O= value", () => {
    expect(PUBLISHER_PIN_RE.test("O=Microsoft Corporation")).toBe(true);
    expect(PUBLISHER_PIN_RE.test("Google")).toBe(false);
    expect(PUBLISHER_PIN_RE.test("CN=Google LLC")).toBe(false);
  });
});

describe("publisher pin lists (vendor renamed its certificate organisation)", () => {
  const pins = "O=Eclipse Foundation; O=Eclipse.org Foundation, Inc.";
  it("accepts any listed organisation exactly", () => {
    expect(PUBLISHER_PIN_RE.test(pins)).toBe(true);
    expect(orgMatches("CN=x\r\nO=Eclipse Foundation", pins)).toBe(true);
    expect(orgMatches('CN=x, O="Eclipse.org Foundation, Inc."', pins)).toBe(true);
  });
  it("still rejects anything else and stays exact", () => {
    expect(orgMatches("CN=x, O=Eclipse Foundation Evil", pins)).toBe(false);
    expect(orgMatches("CN=x, O=Evil", pins)).toBe(false);
  });
  it("caps the list at 4 pins and rejects malformed entries", () => {
    expect(PUBLISHER_PIN_RE.test("O=A1; O=B2; O=C3; O=D4; O=E5")).toBe(false);
    expect(PUBLISHER_PIN_RE.test("O=Good; CN=Bad")).toBe(false);
    expect(PUBLISHER_PIN_RE.test("O=Good;")).toBe(false);
  });
});
