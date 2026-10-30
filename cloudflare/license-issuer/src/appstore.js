// App Store signed data (StoreKit 2 transactions, Server Notifications V2),
// verified offline: an ES256 JWS whose `x5c` header carries leaf, intermediate
// and Apple Root CA G3. Each certificate must be signed by the next, the root
// must match the pinned SHA-256, the leaf and intermediate must carry Apple's
// marker OIDs, and every certificate must be valid at the payload's
// `signedDate`. X.509 is read with the small DER reader below (no dependency).

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// SHA-256 of the DER of Apple Root CA G3
// (https://www.apple.com/certificateauthority/AppleRootCA-G3.cer).
export const APPLE_ROOT_G3_SHA256 = "63343abfb89a6a03ebb57e9b3f5fa7be7c4f5c756f3017b3a8c488c3653e9179";

// Apple marker extensions: the App Store receipt-signing leaf and the WWDR intermediate.
export const OID_APPLE_LEAF = "1.2.840.113635.100.6.11.1";
export const OID_APPLE_INTERMEDIATE = "1.2.840.113635.100.6.2.1";

const SIG_HASH = { "1.2.840.10045.4.3.2": "SHA-256", "1.2.840.10045.4.3.3": "SHA-384" };
const CURVES = { "1.2.840.10045.3.1.7": ["P-256", 32], "1.3.132.0.34": ["P-384", 48] };

export class AppleJwsError extends Error {
  constructor(code) {
    super(`apple jws: ${code}`);
    this.code = code;
  }
}

const fail = (code) => {
  throw new AppleJwsError(code);
};

// --- DER reader ---------------------------------------------------------------

// One TLV at `pos`: { tag, start (of contents), end, raw (whole TLV) }.
function readTlv(bytes, pos) {
  if (pos + 2 > bytes.length) fail("bad-format");
  const tag = bytes[pos];
  let len = bytes[pos + 1];
  let start = pos + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 4 || start + n > bytes.length) fail("bad-format");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + bytes[start + i];
    start += n;
  }
  const end = start + len;
  if (end > bytes.length) fail("bad-format");
  return { tag, start, end, raw: bytes.subarray(pos, end), body: bytes.subarray(start, end) };
}

function children(bytes, tlv) {
  const out = [];
  for (let pos = tlv.start; pos < tlv.end; ) {
    const child = readTlv(bytes, pos);
    out.push(child);
    pos = child.end;
  }
  return out;
}

function oidText(body) {
  const parts = [Math.floor(body[0] / 40), body[0] % 40];
  let value = 0;
  for (let i = 1; i < body.length; i++) {
    value = value * 128 + (body[i] & 0x7f);
    if (!(body[i] & 0x80)) {
      parts.push(value);
      value = 0;
    }
  }
  return parts.join(".");
}

function timeMs(tlv) {
  const s = decoder.decode(tlv.body);
  const m = tlv.tag === 0x17 ? /^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s) : /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})Z$/.exec(s);
  if (!m) fail("bad-format");
  let year = Number(m[1]);
  if (tlv.tag === 0x17) year += year < 50 ? 2000 : 1900;
  return Date.UTC(year, Number(m[2]) - 1, Number(m[3]), Number(m[4]), Number(m[5]), Number(m[6]));
}

// The parts of an X.509 certificate this verifier needs.
export function parseCertificate(der) {
  const cert = readTlv(der, 0);
  if (cert.tag !== 0x30 || cert.end !== der.length) fail("bad-format");
  const [tbs, sigAlg, sigValue] = children(der, cert);
  if (!tbs || !sigAlg || !sigValue || sigValue.tag !== 0x03) fail("bad-format");
  const fields = children(der, tbs);
  let i = fields[0]?.tag === 0xa0 ? 1 : 0; // optional [0] version
  i += 2; // serial, signature algorithm
  i += 1; // issuer
  const validity = fields[i++];
  i += 1; // subject
  const spki = fields[i++];
  if (!validity || !spki) fail("bad-format");
  const [notBefore, notAfter] = children(der, validity);
  const extensions = new Set();
  for (const field of fields.slice(i)) {
    if (field.tag !== 0xa3) continue;
    const [list] = children(der, field);
    for (const ext of children(der, list)) extensions.add(oidText(children(der, ext)[0].body));
  }
  const [spkiAlg] = children(der, spki);
  const [, curveOid] = children(der, spkiAlg);
  const curve = curveOid ? CURVES[oidText(curveOid.body)] : undefined;
  const hash = SIG_HASH[oidText(children(der, sigAlg)[0].body)];
  if (!curve || !hash) fail("bad-format");
  return {
    tbs: tbs.raw,
    signatureHash: hash,
    signature: sigValue.body.subarray(1), // skip the unused-bits byte
    spki: spki.raw,
    curve,
    notBefore: timeMs(notBefore),
    notAfter: timeMs(notAfter),
    extensions,
  };
}

// DER ECDSA-Sig-Value (SEQUENCE { r INTEGER, s INTEGER }) -> raw r||s for WebCrypto.
function derSignatureToRaw(sig, size) {
  const seq = readTlv(sig, 0);
  const parts = children(sig, seq);
  if (seq.tag !== 0x30 || parts.length !== 2) fail("bad-signature");
  const out = new Uint8Array(size * 2);
  parts.forEach((part, n) => {
    let v = part.body;
    while (v.length > size && v[0] === 0) v = v.subarray(1);
    if (v.length > size) fail("bad-signature");
    out.set(v, n * size + size - v.length);
  });
  return out;
}

function importKey(cert) {
  return crypto.subtle.importKey("spki", cert.spki, { name: "ECDSA", namedCurve: cert.curve[0] }, false, ["verify"]);
}

async function signedBy(child, parent) {
  let raw;
  try {
    raw = derSignatureToRaw(child.signature, parent.curve[1]);
  } catch {
    return false;
  }
  const key = await importKey(parent);
  return crypto.subtle.verify({ name: "ECDSA", hash: child.signatureHash }, key, raw, child.tbs);
}

// --- JWS ----------------------------------------------------------------------

function fromBase64Url(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9_-]*$/.test(text)) fail("bad-format");
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4)), (c) => c.charCodeAt(0));
}

function fromBase64(text) {
  if (typeof text !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(text)) fail("bad-format");
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function hex(bytes) {
  return Array.from(new Uint8Array(bytes), (b) => b.toString(16).padStart(2, "0")).join("");
}

function parseJson(bytes) {
  try {
    const value = JSON.parse(decoder.decode(bytes));
    if (value === null || typeof value !== "object" || Array.isArray(value)) fail("bad-format");
    return value;
  } catch (error) {
    if (error instanceof AppleJwsError) throw error;
    return fail("bad-format");
  }
}

// Returns the decoded payload of an Apple-signed JWS, or throws AppleJwsError.
// `rootSha256` is the pinned root (APPLE_ROOT_G3_SHA256 in production; tests
// pass their own); `now` is used only when the payload has no `signedDate`.
export async function verifyAppleJws(jws, { rootSha256, now } = {}) {
  if (typeof jws !== "string" || jws.length > 32 * 1024) fail("bad-format");
  const segments = jws.split(".");
  if (segments.length !== 3) fail("bad-format");
  const header = parseJson(fromBase64Url(segments[0]));
  const payload = parseJson(fromBase64Url(segments[1]));
  const signature = fromBase64Url(segments[2]);
  if (header.alg !== "ES256" || !Array.isArray(header.x5c) || header.x5c.length !== 3) fail("bad-format");
  const ders = header.x5c.map(fromBase64);
  const [leaf, intermediate, root] = ders.map(parseCertificate);

  const rootHash = hex(await crypto.subtle.digest("SHA-256", ders[2]));
  if (typeof rootSha256 !== "string" || rootHash !== rootSha256.toLowerCase()) fail("bad-chain");
  if (!(await signedBy(leaf, intermediate)) || !(await signedBy(intermediate, root))) fail("bad-chain");

  if (leaf.curve[0] !== "P-256" || signature.length !== 64) fail("bad-signature");
  const key = await importKey(leaf);
  const signingInput = encoder.encode(`${segments[0]}.${segments[1]}`);
  if (!(await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, signature, signingInput))) {
    fail("bad-signature");
  }

  if (!leaf.extensions.has(OID_APPLE_LEAF) || !intermediate.extensions.has(OID_APPLE_INTERMEDIATE)) fail("bad-oid");

  const at = Number.isFinite(payload.signedDate) ? payload.signedDate : (now ?? new Date()).getTime();
  for (const cert of [leaf, intermediate, root]) {
    if (at < cert.notBefore || at > cert.notAfter) fail("expired");
  }
  return payload;
}

// An App Store Server Notification V2 body ({"signedPayload": ...}): verifies
// the notification and the transaction inside it. Returns
// { notificationType, subtype, notificationUUID, environment, transaction }.
export async function decodeNotification(signedPayload, options) {
  const notification = await verifyAppleJws(signedPayload, options);
  const signedTransaction = notification.data?.signedTransactionInfo;
  const transaction = signedTransaction === undefined ? null : await verifyAppleJws(signedTransaction, options);
  return {
    notificationType: notification.notificationType,
    subtype: notification.subtype,
    notificationUUID: notification.notificationUUID,
    environment: notification.data?.environment,
    transaction,
  };
}
