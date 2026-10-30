// Fake Google endpoints for the Play tests: OAuth token exchange and the Play
// Developer API purchase lookup. TEST ONLY: the service account is throwaway.
import assert from "node:assert/strict";
import crypto from "node:crypto";

import { NOW } from "./store-helpers.mjs";

export const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
export const SERVICE_ACCOUNT = JSON.stringify({
  type: "service_account",
  client_email: "lgk-test@example.iam.gserviceaccount.com",
  private_key: privateKey.export({ type: "pkcs8", format: "pem" }),
  token_uri: "https://oauth2.googleapis.com/token",
});

export const PURCHASE_URL =
  "https://androidpublisher.googleapis.com/androidpublisher/v3/applications/app.localgatekeys.android/purchases/products/pro_unlimited/tokens/";

// purchases: token -> purchase JSON, or a number for an HTTP error status.
export function fakeGoogle(purchases = {}, { tokenStatus = 200 } = {}) {
  const calls = [];
  async function fetchImpl(url, init = {}) {
    url = String(url);
    calls.push({ url, init });
    if (url === "https://oauth2.googleapis.com/token") {
      const form = new URLSearchParams(init.body);
      assert.equal(form.get("grant_type"), "urn:ietf:params:oauth:grant-type:jwt-bearer");
      const [h, p, s] = form.get("assertion").split(".");
      const claims = JSON.parse(Buffer.from(p, "base64url"));
      assert.equal(claims.scope, "https://www.googleapis.com/auth/androidpublisher");
      assert.equal(claims.iss, "lgk-test@example.iam.gserviceaccount.com");
      assert.ok(crypto.verify("sha256", Buffer.from(`${h}.${p}`), publicKey, Buffer.from(s, "base64url")), "RS256 assertion");
      if (tokenStatus !== 200) return new Response("{}", { status: tokenStatus });
      return Response.json({ access_token: "ya29.test-access", expires_in: 3599, token_type: "Bearer" });
    }
    if (url.startsWith(PURCHASE_URL)) {
      assert.equal(new Headers(init.headers).get("Authorization"), "Bearer ya29.test-access");
      const purchase = purchases[decodeURIComponent(url.slice(PURCHASE_URL.length))];
      if (purchase === undefined) return new Response("{}", { status: 404 });
      if (typeof purchase === "number") return new Response("{}", { status: purchase });
      return Response.json({ kind: "androidpublisher#productPurchase", ...purchase });
    }
    return fetchImpl.fallback ? fetchImpl.fallback(url, init) : new Response("{}", { status: 404 });
  }
  fetchImpl.calls = calls;
  return fetchImpl;
}

export const purchased = (extra = {}) => ({
  orderId: "GPA.3300-1111-2222-33333",
  purchaseState: 0,
  consumptionState: 0,
  acknowledgementState: 1,
  purchaseTimeMillis: String(NOW - 60000),
  ...extra,
});
