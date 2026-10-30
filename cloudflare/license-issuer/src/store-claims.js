// Licences for store purchases (App Store, Google Play) and their revocation.
//
// D1 (binding CLAIMS, migrations/0002_store_claims.sql) holds one row per
// original purchase: the primary key makes the first claim win and every
// repeat claim read back the same licence text. Revocations are written to KV
// as `revoke:` records exactly like Paddle refunds (writeRevocation), so the
// weekly revocation list picks them up.

import { buildLicense, encodePaste, issueBundle, licenseIdForOrder } from "./sign.js";

const TABLES = { appstore_claims: "appstore", play_claims: "play" };
const select = (table) => `SELECT licence_id, licence_text, revoked FROM ${table} WHERE original_id = ?1`;
const insert = (table) =>
  `INSERT INTO ${table} (original_id, licence_id, licence_text, revoked, created_at) VALUES (?1, ?2, ?3, ?4, ?5) ON CONFLICT DO NOTHING`;
const markRevoked = (table) => `UPDATE ${table} SET revoked = 1 WHERE original_id = ?1`;

function checkTable(table) {
  if (!Object.hasOwn(TABLES, table)) throw new Error(`unknown store table ${table}`);
  return TABLES[table];
}

const readRow = (env, table, originalId) => env.CLAIMS.prepare(select(table)).bind(originalId).first();

// The refund / chargeback writer shared by every provider: the record goes
// under `adjustment:<provider>:<id>` and `revoke:<license_id>:<id>`, and doubles
// as metadata so `wrangler kv key list` shows it (< 1 KiB).
export async function writeRevocation(env, provider, adjustmentId, record) {
  const value = JSON.stringify(record);
  await env.LICENSES.put(`adjustment:${provider}:${adjustmentId}`, value, { metadata: record });
  await env.LICENSES.put(`revoke:${record.license_id}:${adjustmentId}`, value, { metadata: record });
}

// One licence per original purchase. Returns { licence } (the LGK1- text, the
// same on every call) or { revoked: true }. `name` is "App Store purchase" or
// "Google Play purchase"; the licence carries no email or other personal data
// (the field is required by every verifier, so it repeats the name).
export async function issueStoreLicence(env, table, originalId, name, now = Date.now()) {
  const provider = checkTable(table);
  const existing = await readRow(env, table, originalId);
  if (existing !== null) return existing.revoked ? { revoked: true } : { licence: existing.licence_text };
  // Sign first: a bad key throws before anything is written.
  const licenseId = await licenseIdForOrder(`order:${provider}:${originalId}`);
  const issuedAt = new Date(now).toISOString().slice(0, 10);
  const license = buildLicense({ name, email: name, issuedAt, licenseId });
  const text = encodePaste(await issueBundle(license, env.LICENSE_PRIVATE_KEY));
  await env.CLAIMS.prepare(insert(table)).bind(originalId, licenseId, text, 0, Math.floor(now / 1000)).run();
  // Read back: a concurrent claim or a refund may have landed first.
  const row = await readRow(env, table, originalId);
  if (row === null || row.revoked || row.licence_text === null) return { revoked: true };
  return { licence: row.licence_text };
}

// Marks the purchase revoked and, if a licence was issued for it, writes the
// `revoke:` record. A purchase never claimed gets a revoked row, so a later
// claim answers 403. Returns the revoked licence id, or null if none was issued.
export async function revokeStoreClaim(env, table, originalId, { adjustmentId, action, occurredAt }, now = Date.now()) {
  const provider = checkTable(table);
  await env.CLAIMS.prepare(insert(table)).bind(originalId, null, null, 1, Math.floor(now / 1000)).run();
  await env.CLAIMS.prepare(markRevoked(table)).bind(originalId).run();
  // Read after the update, so a claim that raced in still gets its revoke record.
  const row = await readRow(env, table, originalId);
  if (row === null || row.licence_id === null) return null;
  await writeRevocation(env, provider, adjustmentId, {
    provider,
    order_id: originalId,
    adjustment_id: adjustmentId,
    license_id: row.licence_id,
    action,
    status: "approved",
    type: "full",
    occurred_at: occurredAt,
    revoke: true,
    reinstate: false,
    recorded_at: new Date(now).toISOString(),
  });
  console.warn(`license-issuer: licence ${row.licence_id} needs revoking (${provider} ${action})`);
  return row.licence_id;
}
