// Tests for the release feed Worker (cloudflare/update-feed). R2 is an
// in-memory fake that applies `range` and `onlyIf` the way R2 does: a failed
// precondition returns the object without a body, a range past the end throws.
import test from "node:test";
import assert from "node:assert/strict";

import worker from "../src/index.js";

const INSTALLER = "releases/0.4.4/LocalGateKeys-0.4.4-setup.exe";
const BYTES = new Uint8Array(1000).map((_, i) => i % 251);
const ETAG = '"abc123"';

// strictLength: refuse a range whose length runs past the end instead of clamping it.
function fakeR2(objects, { strictLength = false } = {}) {
  const calls = [];
  const meta = (key) => ({ key, size: objects[key].length, httpEtag: ETAG, etag: ETAG.slice(1, -1) });
  const failed = (onlyIf) => {
    if (!onlyIf) return false;
    const noneMatch = onlyIf.get("If-None-Match");
    if (noneMatch !== null && (noneMatch.trim() === "*" || noneMatch.split(",").map((t) => t.trim()).includes(ETAG))) {
      return true;
    }
    const match = onlyIf.get("If-Match");
    return match !== null && !match.split(",").map((t) => t.trim()).includes(ETAG);
  };
  return {
    calls,
    async head(key) {
      calls.push(["head", key]);
      return key in objects ? meta(key) : null;
    },
    async get(key, options = {}) {
      calls.push(["get", key, options]);
      if (!(key in objects)) return null;
      const data = objects[key];
      if (failed(options.onlyIf)) return meta(key); // no body
      let start = 0;
      let end = data.length;
      if (options.range) {
        const r = options.range;
        if (r.suffix !== undefined) start = Math.max(0, data.length - r.suffix);
        else {
          start = r.offset ?? 0;
          if (start >= data.length) throw new Error("get: The requested range is not satisfiable (10039)");
          if (r.length !== undefined) {
            if (strictLength && start + r.length > data.length) throw new Error("get: range past the end (10039)");
            end = start + r.length;
          }
        }
      }
      const body = new Blob([data.slice(start, end)]).stream();
      return { ...meta(key), body, range: options.range };
    },
  };
}

const env = () => ({ RELEASES: fakeR2({ [INSTALLER]: BYTES, "stable.json": new TextEncoder().encode('{"a":1}') }) });

const fetchFeed = (e, path, init = {}) => worker.fetch(new Request(`https://updates.example${path}`, init), e);
const bytesOf = async (r) => new Uint8Array(await r.arrayBuffer());

test("a release file is a full 200 with ETag, Accept-Ranges, HSTS and the attachment headers", async () => {
  const r = await fetchFeed(env(), `/${INSTALLER}`);
  assert.equal(r.status, 200);
  assert.deepEqual(await bytesOf(r), BYTES);
  assert.equal(r.headers.get("Content-Length"), "1000");
  assert.equal(r.headers.get("ETag"), ETAG);
  assert.equal(r.headers.get("Accept-Ranges"), "bytes");
  assert.equal(r.headers.get("X-Content-Type-Options"), "nosniff");
  assert.equal(r.headers.get("Content-Type"), "application/octet-stream");
  assert.equal(r.headers.get("Content-Disposition"), 'attachment; filename="LocalGateKeys-0.4.4-setup.exe"');
  assert.equal(r.headers.get("Strict-Transport-Security"), "max-age=63072000; includeSubDomains");
});

test("byte ranges are passed to R2 and answered with 206 and Content-Range", async () => {
  const e = env();
  const cases = [
    ["bytes=0-99", 0, 99],
    ["bytes=900-", 900, 999],
    ["bytes=-10", 990, 999],
    ["bytes=990-5000", 990, 999],
  ];
  for (const [header, start, end] of cases) {
    const r = await fetchFeed(e, `/${INSTALLER}`, { headers: { Range: header } });
    assert.equal(r.status, 206, header);
    assert.equal(r.headers.get("Content-Range"), `bytes ${start}-${end}/1000`, header);
    assert.equal(r.headers.get("Content-Length"), String(end - start + 1), header);
    assert.deepEqual(await bytesOf(r), BYTES.slice(start, end + 1), header);
    assert.equal(r.headers.get("Content-Disposition"), 'attachment; filename="LocalGateKeys-0.4.4-setup.exe"');
  }
  const [, key, options] = e.RELEASES.calls.find((c) => c[0] === "get");
  assert.equal(key, INSTALLER);
  assert.deepEqual(options.range, { offset: 0, length: 100 });
  assert.ok(options.onlyIf instanceof Headers);
});

test("a range running past the end is clamped even if R2 refuses it", async () => {
  const e = { RELEASES: fakeR2({ [INSTALLER]: BYTES }, { strictLength: true }) };
  const r = await fetchFeed(e, `/${INSTALLER}`, { headers: { Range: "bytes=990-5000" } });
  assert.equal(r.status, 206);
  assert.equal(r.headers.get("Content-Range"), "bytes 990-999/1000");
  assert.deepEqual(await bytesOf(r), BYTES.slice(990));
});

test("an unsatisfiable range is 416 with the size; malformed or multiple ranges send the whole file", async () => {
  for (const header of ["bytes=1000-", "bytes=5000-6000", "bytes=-0"]) {
    const r = await fetchFeed(env(), `/${INSTALLER}`, { headers: { Range: header } });
    assert.equal(r.status, 416, header);
    assert.equal(r.headers.get("Content-Range"), "bytes */1000", header);
  }
  for (const header of ["bytes=0-1,5-6", "items=0-1", "bytes=9-3", "bytes=abc"]) {
    const r = await fetchFeed(env(), `/${INSTALLER}`, { headers: { Range: header } });
    assert.equal(r.status, 200, header);
    assert.equal((await bytesOf(r)).length, 1000, header);
  }
  const missing = await fetchFeed(env(), "/releases/0.4.4/nothing.exe", { headers: { Range: "bytes=0-1" } });
  assert.equal(missing.status, 404);
});

test("If-None-Match with the current ETag is 304 without a body; a stale one is a full 200", async () => {
  const hit = await fetchFeed(env(), `/${INSTALLER}`, { headers: { "If-None-Match": ETAG } });
  assert.equal(hit.status, 304);
  assert.equal(hit.headers.get("ETag"), ETAG);
  assert.equal(hit.body, null);
  const stale = await fetchFeed(env(), `/${INSTALLER}`, { headers: { "If-None-Match": '"old"' } });
  assert.equal(stale.status, 200);
  assert.equal((await bytesOf(stale)).length, 1000);
  const changed = await fetchFeed(env(), `/${INSTALLER}`, { headers: { "If-Match": '"old"', Range: "bytes=0-9" } });
  assert.equal(changed.status, 412);
});

test("HEAD still works and sends no body", async () => {
  const e = env();
  const r = await fetchFeed(e, `/${INSTALLER}`, { method: "HEAD" });
  assert.equal(r.status, 200);
  assert.equal(r.headers.get("Content-Length"), "1000");
  assert.equal(r.headers.get("Accept-Ranges"), "bytes");
  assert.equal(r.headers.get("ETag"), ETAG);
  assert.deepEqual(e.RELEASES.calls.map((c) => c[0]), ["head"]);
  assert.equal((await fetchFeed(e, "/releases/0.4.4/none.exe", { method: "HEAD" })).status, 404);
});

test("the feed is served whole, unranged, and other paths and methods are refused", async () => {
  const e = env();
  const feed = await fetchFeed(e, "/stable.json", { headers: { Range: "bytes=0-1" } });
  assert.equal(feed.status, 200);
  assert.equal(await feed.text(), '{"a":1}');
  assert.equal(feed.headers.get("Accept-Ranges"), null);
  assert.equal(feed.headers.get("Strict-Transport-Security"), "max-age=63072000; includeSubDomains");
  assert.equal((await fetchFeed(e, "/stable.json?x=1")).status, 400);
  assert.equal((await fetchFeed(e, "/releases/0.4.4/../x")).status, 404);
  const post = await fetchFeed(e, "/stable.json", { method: "POST", body: "x" });
  assert.equal(post.status, 405);
  assert.equal(post.headers.get("Strict-Transport-Security"), "max-age=63072000; includeSubDomains");
});
