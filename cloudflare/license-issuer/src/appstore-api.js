// App Store Server API: Get Transaction Info, so a claim does not rest on a
// client JWS that may predate a refund whose notification we missed. Needs the
// secrets APPSTORE_API_ISSUER_ID, APPSTORE_API_KEY_ID and
// APPSTORE_API_PRIVATE_KEY (the App Store Connect in-app purchase key, an
// ES256 .p8 PEM). Keys, tokens and Apple's answers are never logged.

import { toBase64Url } from "./sign.js";
import { verifyAppleJws } from "./appstore.js";

export const APPSTORE_API_HOSTS = {
  Production: "https://api.storekit.itunes.apple.com",
  Sandbox: "https://api.storekit-sandbox.itunes.apple.com",
};
const TOKEN_LIFETIME_SECONDS = 20 * 60; // Apple allows at most 60 minutes
const encoder = new TextEncoder();

// `not-found`: Apple does not know the transaction (4xx). `unavailable`: Apple,
// the network or our configuration failed; the app retries later (503).
export class AppStoreApiError extends Error {
  constructor(code) {
    super(`appstore api: ${code}`);
    this.code = code;
  }
}

export function appStoreApiConfigured(env) {
  return [env.APPSTORE_API_ISSUER_ID, env.APPSTORE_API_KEY_ID, env.APPSTORE_API_PRIVATE_KEY].every(
    (v) => typeof v === "string" && v.trim() !== "",
  );
}

function pemToDer(pem) {
  const body = pem.replace(/-----(BEGIN|END) PRIVATE KEY-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0));
}

const b64urlJson = (value) => toBase64Url(encoder.encode(JSON.stringify(value)));

// The ES256 bearer token for the App Store Server API.
export async function appStoreApiToken(env, bundleId, now = Date.now()) {
  let key;
  try {
    key = await crypto.subtle.importKey("pkcs8", pemToDer(env.APPSTORE_API_PRIVATE_KEY), { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]);
  } catch {
    console.error("license-issuer: APPSTORE_API_PRIVATE_KEY does not import");
    throw new AppStoreApiError("unavailable");
  }
  const iat = Math.floor(now / 1000);
  const input = `${b64urlJson({ alg: "ES256", kid: env.APPSTORE_API_KEY_ID.trim(), typ: "JWT" })}.${b64urlJson({
    iss: env.APPSTORE_API_ISSUER_ID.trim(),
    iat,
    exp: iat + TOKEN_LIFETIME_SECONDS,
    aud: "appstoreconnect-v1",
    bid: bundleId,
  })}`;
  // WebCrypto ECDSA signatures are raw r||s, which is what JWS ES256 wants.
  const sig = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, encoder.encode(input)));
  return `${input}.${toBase64Url(sig)}`;
}

// Get Transaction Info: Apple's current, verified view of `transactionId`.
// `appleOptions` are the verifyAppleJws options (pinned root, clock).
export async function getAppStoreTransaction(env, { transactionId, environment, bundleId }, fetchImpl, appleOptions, now = Date.now()) {
  const host = APPSTORE_API_HOSTS[environment];
  if (!host) throw new AppStoreApiError("not-found");
  const token = await appStoreApiToken(env, bundleId, now);
  let response;
  try {
    response = await fetchImpl(`${host}/inApps/v1/transactions/${encodeURIComponent(transactionId)}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
  } catch {
    throw new AppStoreApiError("unavailable");
  }
  if (!response.ok) {
    if (response.status === 401 || response.status === 403) {
      console.error(`license-issuer: Apple refused the App Store Server API key (${response.status})`);
    }
    if ([401, 403, 408, 429].includes(response.status) || response.status >= 500) throw new AppStoreApiError("unavailable");
    throw new AppStoreApiError("not-found");
  }
  let body;
  try {
    body = await response.json();
  } catch {
    throw new AppStoreApiError("unavailable");
  }
  try {
    return await verifyAppleJws(body?.signedTransactionInfo, appleOptions);
  } catch {
    console.error("license-issuer: Apple's Get Transaction Info answer did not verify");
    throw new AppStoreApiError("unavailable");
  }
}
