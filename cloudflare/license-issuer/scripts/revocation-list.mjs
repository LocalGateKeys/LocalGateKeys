// Turns the refund / chargeback records the Worker keeps in KV into the list of
// licence ids to revoke, one per line, for `sign_release_manifest.py revocations`.
//
//   npx wrangler kv key list --binding LICENSES --prefix revoke: --remote > revoke-keys.json
//   node cloudflare/license-issuer/scripts/revocation-list.mjs revoke-keys.json [--existing revoked.txt] > revoked.txt
//
// `wrangler kv key list` prints [{ name, metadata }, ...]; the Worker stores each
// record as the key's metadata, so no value has to be fetched. For each licence
// the newest decisive record wins: a full refund or chargeback revokes, a
// reversed chargeback or a rejected / reversed refund reinstates. Partial
// refunds and warnings decide nothing and are listed on stderr for review.
// Ids already in --existing stay in the list (the signed list replaces the
// previous one, so dropping them would un-revoke them); a reinstated one is
// reported on stderr so you can remove it by hand if that is what you want.

import fs from "node:fs";
import { fileURLToPath } from "node:url";

const LICENSE_ID = /^lgk_[0-9A-HJKMNP-TV-Z]{26}$/;

function when(record) {
  return String(record.occurred_at ?? record.recorded_at ?? "");
}

// entries: [{ name, metadata }]; existing: iterable of ids. Returns { ids, review, reinstated }.
export function revocationIds(entries, existing = []) {
  const byLicence = new Map();
  const review = [];
  for (const entry of entries) {
    const record = entry?.metadata;
    if (!record || !LICENSE_ID.test(String(record.license_id ?? ""))) continue;
    if (!record.revoke && !record.reinstate) {
      review.push(record);
      continue;
    }
    const list = byLicence.get(record.license_id) ?? [];
    list.push(record);
    byLicence.set(record.license_id, list);
  }
  const ids = new Set();
  const reinstated = [];
  for (const id of existing) if (LICENSE_ID.test(id)) ids.add(id);
  for (const [id, records] of byLicence) {
    records.sort((a, b) => (when(a) < when(b) ? -1 : when(a) > when(b) ? 1 : 0));
    const last = records[records.length - 1];
    if (last.revoke) ids.add(id);
    else if (ids.has(id)) reinstated.push(id);
  }
  return { ids: [...ids].sort(), review, reinstated };
}

function readExisting(path) {
  return fs
    .readFileSync(path, "utf8")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"));
}

function main(argv) {
  const args = [...argv];
  let existing = [];
  const at = args.indexOf("--existing");
  if (at !== -1) {
    existing = readExisting(args[at + 1]);
    args.splice(at, 2);
  }
  if (args.length !== 1) {
    console.error("usage: revocation-list.mjs <wrangler kv key list output.json> [--existing revoked.txt]");
    return 2;
  }
  const entries = JSON.parse(fs.readFileSync(args[0], "utf8"));
  const { ids, review, reinstated } = revocationIds(entries, existing);
  for (const record of review) {
    console.error(
      `review: ${record.license_id} ${record.action} ${record.type ?? ""} ${record.status ?? ""} (order ${record.order_id}, ${record.adjustment_id})`,
    );
  }
  for (const id of reinstated) console.error(`reinstated but still listed (remove by hand if intended): ${id}`);
  process.stdout.write(ids.map((id) => `${id}\n`).join(""));
  return 0;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === fs.realpathSync(process.argv[1])) {
  process.exitCode = main(process.argv.slice(2));
}
