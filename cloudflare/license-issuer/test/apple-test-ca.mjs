// A throwaway stand-in for Apple's signing chain: root (P-384, SHA-384),
// intermediate (P-256, signed with SHA-384) and leaf (P-256, signed with
// SHA-256), with Apple's marker OIDs, built with WebCrypto and the minimal DER
// writer below. TEST ONLY: nothing it signs is real.
import crypto from "node:crypto";

import { OID_APPLE_INTERMEDIATE, OID_APPLE_LEAF } from "../src/appstore.js";

const subtle = crypto.webcrypto.subtle;
const encoder = new TextEncoder();

// --- DER writer ---------------------------------------------------------------

function tlv(tag, body) {
  const len = body.length;
  let head;
  if (len < 0x80) head = [len];
  else if (len < 0x100) head = [0x81, len];
  else if (len < 0x10000) head = [0x82, len >> 8, len & 0xff];
  else head = [0x83, len >> 16, (len >> 8) & 0xff, len & 0xff];
  return Uint8Array.from([tag, ...head, ...body]);
}

const concat = (...parts) => Uint8Array.from(parts.flatMap((p) => [...p]));
const seq = (...items) => tlv(0x30, concat(...items));
const set = (...items) => tlv(0x31, concat(...items));

function integer(bytes) {
  let b = [...bytes];
  while (b.length > 1 && b[0] === 0 && !(b[1] & 0x80)) b = b.slice(1);
  if (b[0] & 0x80) b = [0, ...b];
  return tlv(0x02, Uint8Array.from(b));
}

function oid(text) {
  const parts = text.split(".").map(Number);
  const out = [parts[0] * 40 + parts[1]];
  for (const part of parts.slice(2)) {
    const chunk = [];
    let v = part;
    do {
      chunk.unshift(v & 0x7f);
      v = Math.floor(v / 128);
    } while (v > 0);
    for (let i = 0; i < chunk.length - 1; i++) chunk[i] |= 0x80;
    out.push(...chunk);
  }
  return tlv(0x06, Uint8Array.from(out));
}

const generalizedTime = (ms) =>
  tlv(0x18, encoder.encode(new Date(ms).toISOString().replace(/[-:T]/g, "").slice(0, 14) + "Z"));
const name = (cn) => seq(set(seq(oid("2.5.4.3"), tlv(0x0c, encoder.encode(cn)))));
const explicit = (n, body) => tlv(0xa0 + n, body);

const ALG = {
  "SHA-256": "1.2.840.10045.4.3.2",
  "SHA-384": "1.2.840.10045.4.3.3",
};

// raw r||s -> DER ECDSA-Sig-Value
function rawToDer(raw) {
  const half = raw.length / 2;
  return seq(integer(raw.subarray(0, half)), integer(raw.subarray(half)));
}

async function makeCert({ subject, issuer, publicKey, signingKey, hash, oids, notBefore, notAfter, serial }) {
  const spki = new Uint8Array(await subtle.exportKey("spki", publicKey));
  const algorithm = seq(oid(ALG[hash]));
  const extensions = oids.map((o) => seq(oid(o), tlv(0x04, Uint8Array.from([0x05, 0x00]))));
  const tbs = seq(
    explicit(0, integer([2])),
    integer([serial]),
    algorithm,
    name(issuer),
    seq(generalizedTime(notBefore), generalizedTime(notAfter)),
    name(subject),
    spki,
    ...(extensions.length ? [explicit(3, seq(...extensions))] : []),
  );
  const raw = new Uint8Array(await subtle.sign({ name: "ECDSA", hash }, signingKey, tbs));
  return seq(tbs, algorithm, tlv(0x03, concat([0], rawToDer(raw))));
}

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const b64url = (bytes) => Buffer.from(bytes).toString("base64url");
const keyPair = (curve) => subtle.generateKey({ name: "ECDSA", namedCurve: curve }, true, ["sign", "verify"]);

const YEAR = 365 * 24 * 3600 * 1000;
export const CA_NOT_BEFORE = Date.parse("2020-01-01T00:00:00Z");

// Options: `leafOid: false` drops the leaf marker OID; `leafNotAfter` (ms) ends the leaf early.
export async function makeTestCa({ leafOid = true, leafNotAfter } = {}) {
  const [rootKeys, intKeys, leafKeys] = await Promise.all([keyPair("P-384"), keyPair("P-256"), keyPair("P-256")]);
  const notBefore = CA_NOT_BEFORE;
  const notAfter = notBefore + 20 * YEAR;
  const root = await makeCert({
    subject: "Test Root CA G3", issuer: "Test Root CA G3", publicKey: rootKeys.publicKey, signingKey: rootKeys.privateKey,
    hash: "SHA-384", oids: [], notBefore, notAfter, serial: 1,
  });
  const intermediate = await makeCert({
    subject: "Test WWDR", issuer: "Test Root CA G3", publicKey: intKeys.publicKey, signingKey: rootKeys.privateKey,
    hash: "SHA-384", oids: [OID_APPLE_INTERMEDIATE], notBefore, notAfter, serial: 2,
  });
  const leaf = await makeCert({
    subject: "Test StoreKit", issuer: "Test WWDR", publicKey: leafKeys.publicKey, signingKey: intKeys.privateKey,
    hash: "SHA-256", oids: leafOid ? [OID_APPLE_LEAF] : [], notBefore, notAfter: leafNotAfter ?? notAfter, serial: 3,
  });
  const rootSha256 = Buffer.from(await subtle.digest("SHA-256", root)).toString("hex");
  const x5c = [leaf, intermediate, root].map(b64);
  async function sign(payload) {
    const header = b64url(encoder.encode(JSON.stringify({ alg: "ES256", x5c })));
    const body = b64url(encoder.encode(JSON.stringify(payload)));
    const sig = await subtle.sign({ name: "ECDSA", hash: "SHA-256" }, leafKeys.privateKey, encoder.encode(`${header}.${body}`));
    return `${header}.${body}.${b64url(new Uint8Array(sig))}`;
  }
  return { rootSha256, x5c, sign };
}

// A StoreKit 2 transaction payload for pro_unlimited, overridable per test.
export function transactionPayload(extra = {}) {
  return {
    transactionId: "2000000111111111",
    originalTransactionId: "2000000111111111",
    bundleId: "app.localgatekeys.app",
    productId: "pro_unlimited",
    purchaseDate: Date.parse("2026-10-29T10:00:00Z"),
    signedDate: Date.parse("2026-10-29T10:00:05Z"),
    environment: "Production",
    type: "Non-Consumable",
    ...extra,
  };
}
