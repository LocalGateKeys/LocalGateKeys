// Tests for the Cloudflare release-feed Worker (cloudflare/update-feed).
// The R2 binding is replaced by an in-memory fake; nothing reaches the network.
const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { pathToFileURL } = require("node:url");

const WORKER = pathToFileURL(path.join(__dirname, "..", "cloudflare", "update-feed", "src", "index.js")).href;

function fakeBucket(objects) {
  const lookups = [];
  const entry = (key) => {
    lookups.push(key);
    if (!Object.hasOwn(objects, key)) return null;
    const bytes = Buffer.from(objects[key]);
    return { size: bytes.length, httpEtag: `"etag-${key}"`, body: bytes };
  };
  return {
    lookups,
    async get(key) {
      return entry(key);
    },
    async head(key) {
      const found = entry(key);
      return found && { size: found.size, httpEtag: found.httpEtag };
    },
  };
}

async function call(pathname, { method = "GET", objects = {} } = {}) {
  const { default: worker } = await import(WORKER);
  const bucket = fakeBucket(objects);
  const response = await worker.fetch(new Request(`https://lgk-updates.example.workers.dev${pathname}`, { method }), {
    RELEASES: bucket,
  });
  return { response, bucket };
}

const FEED = JSON.stringify({ manifest: { sequence: 1 }, signature: {} });

test("serves stable.json byte-for-byte with JSON headers and short caching", async () => {
  const { response } = await call("/stable.json", { objects: { "stable.json": FEED } });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), FEED);
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  assert.equal(response.headers.get("content-length"), String(Buffer.byteLength(FEED)));
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("serves release artifacts as immutable downloads", async () => {
  const { response, bucket } = await call("/releases/0.4.0/LocalGateKeys-Setup-Personal.exe", {
    objects: { "releases/0.4.0/LocalGateKeys-Setup-Personal.exe": "MZ" },
  });
  assert.equal(response.status, 200);
  assert.deepEqual(bucket.lookups, ["releases/0.4.0/LocalGateKeys-Setup-Personal.exe"]);
  assert.equal(response.headers.get("content-type"), "application/octet-stream");
  assert.match(response.headers.get("cache-control"), /immutable/);
  assert.equal(
    response.headers.get("content-disposition"),
    'attachment; filename="LocalGateKeys-Setup-Personal.exe"'
  );
});

test("HEAD returns headers without a body", async () => {
  const { response } = await call("/stable.json", { method: "HEAD", objects: { "stable.json": FEED } });
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("content-length"), String(Buffer.byteLength(FEED)));
  assert.equal(await response.text(), "");
});

test("refuses a feed larger than the client's 64 KB cap", async () => {
  const { response } = await call("/stable.json", { objects: { "stable.json": "x".repeat(65537) } });
  assert.equal(response.status, 500);
});

test("missing objects are 404", async () => {
  assert.equal((await call("/stable.json")).response.status, 404);
  assert.equal((await call("/releases/0.4.0/missing.exe")).response.status, 404);
});

test("anything outside the two allowed path shapes never touches the bucket", async () => {
  for (const pathname of [
    "/",
    "/STABLE.JSON",
    "/stable.json/",
    "/releases/0.4/setup.exe",
    "/releases/v0.4.0/setup.exe",
    "/releases/01.4.0/setup.exe",
    "/releases/0.4.0/",
    "/releases/0.4.0/.hidden",
    "/releases/0.4.0/a..exe",
    "/releases/0.4.0/sub/setup.exe",
    "/releases/0.4.0/%2e%2e",
  ]) {
    const { response, bucket } = await call(pathname, { objects: { "stable.json": FEED } });
    assert.equal(response.status, 404, pathname);
    assert.deepEqual(bucket.lookups, [], pathname);
  }
});

test("only GET and HEAD are allowed", async () => {
  const { response, bucket } = await call("/stable.json", { method: "POST", objects: { "stable.json": FEED } });
  assert.equal(response.status, 405);
  assert.equal(response.headers.get("allow"), "GET, HEAD");
  assert.deepEqual(bucket.lookups, []);
});

test("query strings are rejected so caches hold one copy of the feed", async () => {
  const { response } = await call("/stable.json?v=2", { objects: { "stable.json": FEED } });
  assert.equal(response.status, 400);
});

test("never redirects", async () => {
  for (const pathname of ["/stable.json", "/", "/releases/0.4.0/x.exe"]) {
    const { response } = await call(pathname, { objects: { "stable.json": FEED } });
    assert.ok(response.status < 300 || response.status >= 400, pathname);
    assert.equal(response.headers.get("location"), null, pathname);
  }
});

const REVOCATIONS = JSON.stringify({ manifest: { revoked: [] }, signature: {} });

test("serves revocations.json with the same headers as the feed", async () => {
  const { response, bucket } = await call("/revocations.json", { objects: { "revocations.json": REVOCATIONS } });
  assert.equal(response.status, 200);
  assert.equal(await response.text(), REVOCATIONS);
  assert.deepEqual(bucket.lookups, ["revocations.json"]);
  assert.equal(response.headers.get("content-type"), "application/json; charset=utf-8");
  assert.equal(response.headers.get("cache-control"), "public, max-age=300");
  assert.equal(response.headers.get("x-content-type-options"), "nosniff");
});

test("revocations.json allows up to 1 MiB, the client's bound, and no more", async () => {
  const ok = await call("/revocations.json", { objects: { "revocations.json": "x".repeat(1024 * 1024) } });
  assert.equal(ok.response.status, 200);
  const big = await call("/revocations.json", { objects: { "revocations.json": "x".repeat(1024 * 1024 + 1) } });
  assert.equal(big.response.status, 500);
});

test("404 for other json", async () => {
  const { response, bucket } = await call("/other.json", { objects: { "other.json": "{}" } });
  assert.equal(response.status, 404);
  assert.deepEqual(bucket.lookups, []);
});
