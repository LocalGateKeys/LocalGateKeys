// In-memory stand-in for the D1 binding CLAIMS (migrations/0001_claims.sql).
// Supports exactly the statements src/index.js prepares: the claim lookup and
// the INSERT ... ON CONFLICT DO NOTHING. Each call awaits a tick first so
// concurrent webhooks interleave; the insert itself is atomic, like SQLite.
// `fakeD1({ fail: true })` throws on every statement (a D1 outage).
export function fakeD1({ fail = false } = {}) {
  const rows = new Map(); // claim -> row
  const tick = () => new Promise((r) => setTimeout(r, 1));
  function statement(sql, args = []) {
    const op = sql.trim().split(/\s+/)[0].toUpperCase();
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
  return { rows, prepare: (sql) => statement(sql) };
}
