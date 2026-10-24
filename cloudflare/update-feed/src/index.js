// LocalGateKeys release feed: a read-only view of one R2 bucket.
//
// Serves exactly three kinds of path and nothing else:
//   /stable.json                    -> R2 key "stable.json" (the signed bundle)
//   /revocations.json               -> R2 key "revocations.json" (signed licence revocations)
//   /releases/<x.y.z>/<artifact>    -> R2 key "releases/<x.y.z>/<artifact>"
//
// The desktop client rejects cross-origin redirects and reads at most 64 KB of
// the feed, so this Worker never redirects and serves the feed byte-for-byte.
// Integrity comes from the Ed25519 signature inside stable.json, not from this
// Worker: a compromised Worker can only make checks fail, never pass.

const FEED_PATH = "/stable.json";
const FEED_KEY = "stable.json";
const MAX_FEED_BYTES = 65536;
const REVOCATIONS_PATH = "/revocations.json";
const REVOCATIONS_KEY = "revocations.json";
// Mirrors MAX_REVOCATIONS_BYTES in src/localvault/updates.py.
const MAX_REVOCATIONS_BYTES = 1024 * 1024;

// Mirrors _VERSION_PATTERN and _ARTIFACT_NAME_PATTERN in src/localvault/updates.py.
const RELEASE_PATH =
  /^\/releases\/((?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*))\/([A-Za-z0-9][A-Za-z0-9._-]{0,127})$/;

const BASE_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // No `preload` until the owner decides on it.
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
};

// One byte range ("bytes=a-b", "bytes=a-", "bytes=-n"). Anything else (several
// ranges, other units, garbage) is ignored and the whole file is sent, as
// RFC 9110 allows.
const SINGLE_RANGE = /^bytes=(?:(\d{1,15})-(\d{0,15})|-(\d{1,15}))$/;

function parseRange(header) {
  const match = SINGLE_RANGE.exec((header ?? "").trim());
  if (match === null) return null;
  if (match[3] !== undefined) {
    const suffix = Number(match[3]);
    return suffix === 0 ? "unsatisfiable" : { suffix };
  }
  const offset = Number(match[1]);
  if (match[2] === "") return { offset };
  const last = Number(match[2]);
  if (last < offset) return null; // invalid: ignored
  return { offset, length: last - offset + 1 };
}

// The [start, end] a range covers in an object of `size` bytes, or null if
// none of it exists (416).
function rangeBounds(range, size) {
  if (range.suffix !== undefined) {
    return size === 0 ? null : [Math.max(0, size - range.suffix), size - 1];
  }
  if (range.offset >= size) return null;
  const end = range.length === undefined ? size - 1 : Math.min(size - 1, range.offset + range.length - 1);
  return [range.offset, end];
}

function plain(status, message, extra = {}) {
  return new Response(`${message}\n`, {
    status,
    headers: { ...BASE_HEADERS, "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store", ...extra },
  });
}

function resolve(pathname) {
  if (pathname === FEED_PATH) {
    return {
      key: FEED_KEY,
      contentType: "application/json; charset=utf-8",
      // Short so a new release is seen within minutes; clients only check on demand.
      cacheControl: "public, max-age=300",
      maxBytes: MAX_FEED_BYTES,
    };
  }
  if (pathname === REVOCATIONS_PATH) {
    return {
      key: REVOCATIONS_KEY,
      contentType: "application/json; charset=utf-8",
      cacheControl: "public, max-age=300",
      maxBytes: MAX_REVOCATIONS_BYTES,
    };
  }
  const match = RELEASE_PATH.exec(pathname);
  if (match === null || match[2].includes("..")) {
    return null;
  }
  return {
    key: `releases/${match[1]}/${match[2]}`,
    contentType: "application/octet-stream",
    // Released files never change; a fix ships as a new version.
    cacheControl: "public, max-age=31536000, immutable",
    maxBytes: null,
    filename: match[2],
    version: match[1],
  };
}

// Releases older than MIN_RELEASE (a wrangler var, "x.y.z") are no longer
// offered: they lack later security fixes. The objects stay in R2, so raising
// or removing the var brings them back. Without the var every release is served.
function compareVersions(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < 3; i += 1) {
    if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  }
  return 0;
}

function retired(target, env) {
  const floor = env.MIN_RELEASE;
  return typeof floor === "string" && /^\d+\.\d+\.\d+$/.test(floor) && compareVersions(target.version, floor) < 0;
}

function objectHeaders(target, object) {
  const headers = {
    ...BASE_HEADERS,
    "Content-Type": target.contentType,
    "Content-Length": String(object.size),
    "Cache-Control": target.cacheControl,
    ETag: object.httpEtag,
  };
  if (target.filename !== undefined) {
    headers["Content-Disposition"] = `attachment; filename="${target.filename}"`;
    headers["Accept-Ranges"] = "bytes";
  }
  return headers;
}

// Release files: byte ranges (resumed downloads) and conditional requests
// (If-None-Match and friends) go to R2, which applies them (scan F6).
async function serveRelease(request, env, target) {
  const range = parseRange(request.headers.get("Range"));
  const rangeOf = (size) => (range === null ? undefined : range === "unsatisfiable" ? null : rangeBounds(range, size));
  const unsatisfiable = (size) =>
    plain(416, "Range not satisfiable", { "Content-Range": `bytes */${size}`, "Accept-Ranges": "bytes" });

  if (request.method === "HEAD") {
    const object = await env.RELEASES.head(target.key);
    if (object === null) return plain(404, "Not found");
    return new Response(null, { status: 200, headers: objectHeaders(target, object) });
  }

  const options = { onlyIf: request.headers };
  if (range !== null && range !== "unsatisfiable") options.range = range;
  let object;
  try {
    object = range === "unsatisfiable" ? null : await env.RELEASES.get(target.key, options);
  } catch (error) {
    // R2 rejects a range past the end; anything else is a real failure.
    if (options.range === undefined) throw error;
    object = null;
  }
  if (object === null || (range !== null && object.size !== undefined && rangeOf(object.size) === null)) {
    // Missing object, or a range R2 refused: tell them apart with a HEAD.
    const head = await env.RELEASES.head(target.key);
    if (head === null) return plain(404, "Not found");
    const bounds = range === null ? null : rangeOf(head.size);
    if (range !== null && bounds === null) return unsatisfiable(head.size);
    if (bounds === null) throw new Error(`R2 get failed for ${target.key}`);
    // A range running past the end, if R2 refused it: ask again for what exists.
    object = await env.RELEASES.get(target.key, { ...options, range: { offset: bounds[0], length: bounds[1] - bounds[0] + 1 } });
    if (object === null) return plain(404, "Not found");
  }

  const headers = objectHeaders(target, object);
  if (!("body" in object) || object.body === undefined || object.body === null) {
    // A precondition failed: If-None-Match / If-Modified-Since mean "you have
    // it" (304); If-Match / If-Unmodified-Since mean "it changed" (412).
    delete headers["Content-Length"];
    delete headers["Content-Disposition"];
    const strict = request.headers.has("If-Match") || request.headers.has("If-Unmodified-Since");
    if (strict) return plain(412, "Precondition failed", { ETag: object.httpEtag });
    return new Response(null, { status: 304, headers });
  }
  const bounds = rangeOf(object.size);
  if (bounds === undefined) return new Response(object.body, { status: 200, headers });
  const [start, end] = bounds;
  headers["Content-Length"] = String(end - start + 1);
  headers["Content-Range"] = `bytes ${start}-${end}/${object.size}`;
  return new Response(object.body, { status: 206, headers });
}

export default {
  async fetch(request, env) {
    if (request.method !== "GET" && request.method !== "HEAD") {
      return plain(405, "Method not allowed", { Allow: "GET, HEAD" });
    }
    const url = new URL(request.url);
    if (url.search !== "") {
      return plain(400, "Query strings are not accepted");
    }
    const target = resolve(url.pathname);
    if (target === null) {
      return plain(404, "Not found");
    }

    if (target.filename !== undefined) {
      if (retired(target, env)) {
        return plain(410, "This release is no longer offered. Download the current version from https://localgatekeys.app/download");
      }
      return serveRelease(request, env, target);
    }

    const object =
      request.method === "HEAD" ? await env.RELEASES.head(target.key) : await env.RELEASES.get(target.key);
    if (object === null) {
      return plain(404, "Not found");
    }
    if (target.maxBytes !== null && object.size > target.maxBytes) {
      // Refuse rather than truncate: a truncated feed would fail signature
      // checks with a less obvious error.
      return plain(500, "Feed object is larger than clients accept");
    }

    const headers = objectHeaders(target, object);
    return new Response(request.method === "HEAD" ? null : object.body, { status: 200, headers });
  },
};
