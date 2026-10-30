// Shared fakes for the store-purchase tests (App Store, Google Play).
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { canonicalJson } from "../src/sign.js";
import { fakeD1 } from "./fake-d1.mjs";

// TEST ONLY: the throwaway key from tests/license-issuer.test.cjs. It signs nothing real.
export const PK = "MC4CAQAwBQYDK2VwBCIEIAbQx1FfuhaeywNI9WhH4kiEiWHlqopq/NpubKWX0HYk";
export const NOW = Date.parse("2026-10-29T12:00:00Z");

export function fakeKv() {
  const data = new Map();
  const meta = new Map();
  return {
    data,
    meta,
    async get(key) {
      return data.has(key) ? data.get(key) : null;
    },
    async put(key, value, options) {
      data.set(key, value);
      if (options?.metadata) meta.set(key, options.metadata);
    },
  };
}

export function makeStoreEnv(extra = {}) {
  return {
    LICENSES: fakeKv(),
    CLAIMS: fakeD1(),
    LICENSE_PRIVATE_KEY: PK,
    PRODUCT_IDS: "pro_1",
    PROVIDER: "paddle",
    APPSTORE_BUNDLE_IDS: "app.localgatekeys.app",
    ...extra,
  };
}

export function postJson(path, body, headers = {}) {
  return new Request(`https://licenses.example${path}`, {
    method: "POST",
    body: typeof body === "string" ? body : JSON.stringify(body),
    headers: { "Content-Type": "application/json", "CF-Connecting-IP": "203.0.113.7", ...headers },
  });
}

// Decodes an LGK1- licence and checks its Ed25519 signature with the test public key.
export function verifyLicence(text) {
  assert.match(text, /^LGK1-[A-Za-z0-9_-]+$/);
  const bundle = JSON.parse(Buffer.from(text.slice(5), "base64url").toString("utf8"));
  const pub = crypto.createPublicKey(crypto.createPrivateKey({ key: Buffer.from(PK, "base64"), format: "der", type: "pkcs8" }));
  const ok = crypto.verify(null, Buffer.from(canonicalJson(bundle.license)), pub, Buffer.from(bundle.signature.signature, "base64"));
  assert.ok(ok, "licence signature verifies");
  return bundle.license;
}

export const revokeKeys = (env) => [...env.LICENSES.data.keys()].filter((k) => k.startsWith("revoke:"));
