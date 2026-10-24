// Licence building and signing. Mirrors scripts/issue_license.py and
// localvault.licensing so a licence issued here verifies in the desktop app.

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
// Lifetime updates: the licence covers every build (see licensing.LIFETIME_UNTIL).
export const LIFETIME_UNTIL = "9999-12-31";
const encoder = new TextEncoder();

// Same bytes as updates.canonical_json: sorted keys, no whitespace, UTF-8 kept.
export function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

export function toBase64(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromBase64(text) {
  const bin = atob(text.replace(/\s+/g, ""));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

export function toBase64Url(bytes) {
  return toBase64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// "lgk_" + 26 Crockford base32 characters of 16 random bytes (128 -> 130 bits).
export function newLicenseId(bytes = crypto.getRandomValues(new Uint8Array(16))) {
  let value = 0n;
  for (const b of bytes) value = (value << 8n) | BigInt(b);
  value <<= 2n;
  let out = "";
  for (let shift = 125n; shift >= 0n; shift -= 5n) out += CROCKFORD[Number((value >> shift) & 31n)];
  return `lgk_${out}`;
}

export function newToken() {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

// The licence id of an order ("order:<provider>:<order id>") is derived from
// the order key, so a duplicate or concurrent webhook for the same order signs
// the same licence instead of minting a second one. Licence ids are not secret
// (they sit in the licence and in the revocation list); the hash only makes
// them fixed-length and keeps order ids out of the licence.
export async function licenseIdForOrder(orderKey) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`lgk-license-id:v1:${orderKey}`));
  return newLicenseId(new Uint8Array(digest).slice(0, 16));
}

// A retrieval token for an order whose claim is missing, malformed or bound to
// another order. Deterministic per order (so duplicate deliveries agree) and
// unguessable: an HMAC keyed by a hash of the licence key, which only the
// Worker holds. Same shape as a browser claim (32 bytes, base64url).
export async function fallbackTokenForOrder(orderKey, pkcs8Base64) {
  const keyBytes = await crypto.subtle.digest("SHA-256", encoder.encode(`lgk-retrieval-token-key:v1:${pkcs8Base64}`));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`lgk-retrieval-token:v1:${orderKey}`));
  return toBase64Url(new Uint8Array(mac));
}

// The KV key that counts /recover attempts for one email. An HMAC (keyed like
// the retrieval token, different label) so KV listings show no email addresses.
export async function recoveryThrottleKey(email, pkcs8Base64) {
  const keyBytes = await crypto.subtle.digest("SHA-256", encoder.encode(`lgk-recover-throttle-key:v1:${pkcs8Base64}`));
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const mac = await crypto.subtle.sign("HMAC", key, encoder.encode(`lgk-recover-throttle:v1:${email}`));
  return `recover-throttle:${toBase64Url(new Uint8Array(mac))}`;
}

export function addDays(isoDate, days) {
  const d = new Date(`${isoDate}T00:00:00Z`);
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString().slice(0, 10);
}

export function buildLicense({ name, email, issuedAt, licenseId = newLicenseId() }) {
  return {
    format: 1,
    license_id: licenseId,
    edition: "pro",
    name,
    email,
    issued_at: issuedAt,
    updates_until: LIFETIME_UNTIL,
  };
}

export async function importPrivateKey(pkcs8Base64) {
  // Extractable only so the public half (and so key_id) can be derived from it.
  return crypto.subtle.importKey("pkcs8", fromBase64(pkcs8Base64), { name: "Ed25519" }, true, ["sign"]);
}

export async function publicRawFromPrivate(privateKey) {
  const jwk = await crypto.subtle.exportKey("jwk", privateKey);
  return fromBase64(jwk.x.replace(/-/g, "+").replace(/_/g, "/"));
}

export async function signLicense(license, privateKey, keyId) {
  const sig = await crypto.subtle.sign({ name: "Ed25519" }, privateKey, encoder.encode(canonicalJson(license)));
  return {
    license,
    signature: { alg: "Ed25519", key_id: keyId, signature: toBase64(new Uint8Array(sig)) },
  };
}

export async function keyIdForPublic(rawPublic) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", rawPublic));
  return Array.from(digest.slice(0, 8), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function encodePaste(bundle) {
  return `LGK1-${toBase64Url(encoder.encode(canonicalJson(bundle)))}`;
}

// Signs with the key itself: key_id is derived from it, and the result is checked
// against the derived public key, so a bad key throws instead of selling a dud.
export async function issueBundle(license, pkcs8Base64) {
  const privateKey = await importPrivateKey(pkcs8Base64);
  const publicRaw = await publicRawFromPrivate(privateKey);
  const bundle = await signLicense(license, privateKey, await keyIdForPublic(publicRaw));
  const publicKey = await crypto.subtle.importKey("raw", publicRaw, { name: "Ed25519" }, false, ["verify"]);
  const ok = await crypto.subtle.verify(
    { name: "Ed25519" },
    publicKey,
    fromBase64(bundle.signature.signature),
    encoder.encode(canonicalJson(license)),
  );
  if (!ok) throw new Error("issued licence failed self-verification");
  return bundle;
}
