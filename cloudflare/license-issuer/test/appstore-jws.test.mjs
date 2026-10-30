// App Store JWS verification against a generated test chain (test/apple-test-ca.mjs).
import test from "node:test";
import assert from "node:assert/strict";

import { AppleJwsError, verifyAppleJws } from "../src/appstore.js";
import { makeTestCa, transactionPayload } from "./apple-test-ca.mjs";

const ca = await makeTestCa();

async function rejects(promise, code) {
  await assert.rejects(promise, (error) => error instanceof AppleJwsError && error.code === code);
}

test("valid_chain_returns_payload", async () => {
  const payload = transactionPayload();
  assert.deepEqual(await verifyAppleJws(await ca.sign(payload), { rootSha256: ca.rootSha256 }), payload);
});

test("wrong_root_bad_chain", async () => {
  const other = await makeTestCa();
  await rejects(verifyAppleJws(await ca.sign(transactionPayload()), { rootSha256: other.rootSha256 }), "bad-chain");
  // A chain whose root matches the pin but whose intermediate it did not sign.
  const jws = await ca.sign(transactionPayload());
  const header = JSON.parse(Buffer.from(jws.split(".")[0], "base64url"));
  header.x5c[1] = other.x5c[1];
  const spliced = [Buffer.from(JSON.stringify(header)).toString("base64url"), ...jws.split(".").slice(1)].join(".");
  await rejects(verifyAppleJws(spliced, { rootSha256: ca.rootSha256 }), "bad-chain");
});

test("tampered_payload_bad_signature", async () => {
  const [header, , sig] = (await ca.sign(transactionPayload())).split(".");
  const forged = Buffer.from(JSON.stringify(transactionPayload({ productId: "pro_unlimited", bundleId: "x" }))).toString("base64url");
  await rejects(verifyAppleJws(`${header}.${forged}.${sig}`, { rootSha256: ca.rootSha256 }), "bad-signature");
  await rejects(verifyAppleJws("not a jws", { rootSha256: ca.rootSha256 }), "bad-format");
});

test("missing_oid_bad_oid", async () => {
  const noOid = await makeTestCa({ leafOid: false });
  await rejects(verifyAppleJws(await noOid.sign(transactionPayload()), { rootSha256: noOid.rootSha256 }), "bad-oid");
});

test("expired_leaf_at_signedDate", async () => {
  const short = await makeTestCa({ leafNotAfter: Date.parse("2026-01-01T00:00:00Z") });
  await rejects(verifyAppleJws(await short.sign(transactionPayload()), { rootSha256: short.rootSha256 }), "expired");
  // Signed while the leaf was valid: still accepted after it expired.
  const early = transactionPayload({ signedDate: Date.parse("2025-06-01T00:00:00Z") });
  assert.deepEqual(await verifyAppleJws(await short.sign(early), { rootSha256: short.rootSha256 }), early);
});
