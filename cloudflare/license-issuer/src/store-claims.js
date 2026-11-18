// Licences for store purchases (App Store, Google Play) and their revocation.
//
// D1 (binding CLAIMS, migrations/0002_store_claims.sql) holds one row per
// original purchase: the primary key makes the first claim win and every
// repeat claim read back the same licence text. Revocations are written to KV
// as `revoke:` records exactly like Paddle refunds (writeRevocation), so the
// weekly revocation list picks them up.

import { buildLicense, encodePaste, issueBundle, licenseIdForOrder } from "./sign.js";

const TABLES = { appstore_claims: "appstore", play_claims: "play" };
const select = (table) => `SELECT licence_id, licence_text, revoked, event_at FROM ${table} WHERE original_id = ?1`;
const insert = (table) =>
  `INSERT INTO ${table} (original_id, licence_id, licence_text, revoked, created_at, event_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6) ON CONFLICT DO NOTHING`;
// A refund that arrived before any claim leaves a row with no licence; once the
// refund is reversed, the claim fills that row in (migration 0003 note).
const fillLicence = (table) =>
  `UPDATE ${table} SET licence_id = ?2, licence_text = ?3 WHERE original_id = ?1 AND licence_text IS NULL AND revoked = 0`;
// Revoke / reinstate apply only if the event is not older than the last one
// applied (event_at, ms), so a retried REFUND after a REFUND_REVERSED is a no-op.
const markRevoked = (table) =>
  `UPDATE ${table} SET revoked = 1, event_at = ?2 WHERE original_id = ?1 AND (event_at IS NULL OR event_at <= ?2)`;
const markReinstated = (table) =>
  `UPDATE ${table} SET revoked = 0, event_at = ?2 WHERE original_id = ?1 AND (event_at IS NULL OR event_at <= ?2)`;

const eventMs = (occurredAt, now) => {
  const ms = Date.parse(occurredAt);
  return Number.isFinite(ms) ? ms : now;
};

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
  if (existing !== null && existing.revoked) return { revoked: true };
  if (existing !== null && existing.licence_text !== null) return { licence: existing.licence_text };
  // Sign first: a bad key throws before anything is written.
  const licenseId = await licenseIdForOrder(`order:${provider}:${originalId}`);
  const issuedAt = new Date(now).toISOString().slice(0, 10);
  const license = buildLicense({ name, email: name, issuedAt, licenseId });
  const text = encodePaste(await issueBundle(license, env.LICENSE_PRIVATE_KEY, env));
  if (existing === null) {
    await env.CLAIMS.prepare(insert(table)).bind(originalId, licenseId, text, 0, Math.floor(now / 1000), null).run();
  } else {
    await env.CLAIMS.prepare(fillLicence(table)).bind(originalId, licenseId, text).run();
  }
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
  const at = eventMs(occurredAt, now);
  await env.CLAIMS.prepare(insert(table)).bind(originalId, null, null, 1, Math.floor(now / 1000), at).run();
  const update = await env.CLAIMS.prepare(markRevoked(table)).bind(originalId, at).run();
  if (!update?.meta?.changes) return null; // stale: a newer reinstate already applied
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

// A reversed refund (App Store REFUND_REVERSED): the purchase may be claimed
// again, and a reinstate record (newer occurred_at than the refund) lets the
// revocation-list script report the licence as reinstated.
export async function reinstateStoreClaim(env, table, originalId, { adjustmentId, action, occurredAt }, now = Date.now()) {
  const provider = checkTable(table);
  const update = await env.CLAIMS.prepare(markReinstated(table)).bind(originalId, eventMs(occurredAt, now)).run();
  if (!update?.meta?.changes) return null; // no row, or a newer revoke already applied
  const row = await readRow(env, table, originalId);
  if (row === null || row.licence_id === null) return null;
  await writeRevocation(env, provider, adjustmentId, {
    provider,
    order_id: originalId,
    adjustment_id: adjustmentId,
    license_id: row.licence_id,
    action,
    status: "reversed",
    type: "full",
    occurred_at: occurredAt,
    revoke: false,
    reinstate: true,
    recorded_at: new Date(now).toISOString(),
  });
  console.warn(`license-issuer: licence ${row.licence_id} reinstated (${provider} ${action})`);
  return row.licence_id;
}
