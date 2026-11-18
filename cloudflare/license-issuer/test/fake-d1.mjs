// In-memory stand-in for the D1 binding CLAIMS (migrations/0001_claims.sql and
// 0002_store_claims.sql). Supports exactly the statements the Worker prepares:
// the claim lookup and INSERT ... ON CONFLICT DO NOTHING, and for the store
// tables the row lookup, the insert, the dated `SET revoked = 1` / `0` and the
// licence fill-in for a reinstated refund-before-claim row. Each call awaits a
// tick first so concurrent webhooks interleave; the insert itself is atomic,
// like SQLite. `fakeD1({ fail: true })` throws on every statement (a D1 outage).
export function fakeD1({ fail = false } = {}) {
  const rows = new Map(); // claim -> row
  const store = { appstore_claims: new Map(), play_claims: new Map() }; // original_id -> row
  const tick = () => new Promise((r) => setTimeout(r, 1));
  function storeStatement(op, table, sql, args) {
    return {
      bind: (...values) => storeStatement(op, table, sql, values),
      async run() {
        await tick();
        if (fail) throw new Error("D1_ERROR: fake outage");
        if (op === "INSERT" && /ON CONFLICT DO NOTHING/i.test(sql)) {
          const [original_id, licence_id, licence_text, revoked, created_at, event_at = null] = args;
          if (table.has(original_id)) return { success: true, meta: { changes: 0 } };
          table.set(original_id, { original_id, licence_id, licence_text, revoked, created_at, event_at });
          return { success: true, meta: { changes: 1 } };
        }
        const update = /SET revoked = ([01]), event_at = \?2 WHERE original_id = \?1 AND \(event_at IS NULL OR event_at <= \?2\)/i.exec(sql);
        if (op === "UPDATE" && update) {
          const row = table.get(args[0]);
          const apply = row !== undefined && (row.event_at === null || row.event_at <= args[1]);
          if (apply) Object.assign(row, { revoked: Number(update[1]), event_at: args[1] });
          return { success: true, meta: { changes: apply ? 1 : 0 } };
        }
        if (op === "UPDATE" && /SET licence_id = \?2, licence_text = \?3 WHERE original_id = \?1 AND licence_text IS NULL AND revoked = 0/i.test(sql)) {
          const row = table.get(args[0]);
          const apply = row !== undefined && row.licence_text === null && row.revoked === 0;
          if (apply) Object.assign(row, { licence_id: args[1], licence_text: args[2] });
          return { success: true, meta: { changes: apply ? 1 : 0 } };
        }
        throw new Error(`fake D1: unsupported ${sql}`);
      },
      async first() {
        await tick();
        if (fail) throw new Error("D1_ERROR: fake outage");
        if (op !== "SELECT" || !/WHERE original_id = \?1/i.test(sql)) throw new Error(`fake D1: unsupported ${sql}`);
        const row = table.get(args[0]);
        return row === undefined ? null : { ...row };
      },
    };
  }
  function statement(sql, args = []) {
    const op = sql.trim().split(/\s+/)[0].toUpperCase();
    const storeTable = /\b(appstore_claims|play_claims)\b/.exec(sql);
    if (storeTable) return storeStatement(op, store[storeTable[1]], sql, args);
    return {
      bind: (...values) => statement(sql, values),
      async run() {
        await tick();
        if (fail) throw new Error("D1_ERROR: fake outage");
        if (op !== "INSERT" || !/ON CONFLICT DO NOTHING/i.test(sql)) throw new Error(`fake D1: unsupported ${sql}`);
        const [claim, order_key, licence_id, created_at] = args;
        if (rows.has(claim) || [...rows.values()].some((r) => r.order_key === order_key)) {
          return { success: true, meta: { changes: 0 } };
        }
        rows.set(claim, { claim, order_key, licence_id, created_at });
        return { success: true, meta: { changes: 1 } };
      },
      async first() {
        await tick();
        if (fail) throw new Error("D1_ERROR: fake outage");
        if (op !== "SELECT") throw new Error(`fake D1: unsupported ${sql}`);
        const row = rows.get(args[0]);
        return row === undefined ? null : { ...row };
      },
    };
  }
  return { rows, store, prepare: (sql) => statement(sql) };
}
