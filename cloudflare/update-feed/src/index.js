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
};

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
  };
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

    const headers = {
      ...BASE_HEADERS,
      "Content-Type": target.contentType,
      "Content-Length": String(object.size),
      "Cache-Control": target.cacheControl,
      ETag: object.httpEtag,
    };
    if (target.filename !== undefined) {
      headers["Content-Disposition"] = `attachment; filename="${target.filename}"`;
    }
    return new Response(request.method === "HEAD" ? null : object.body, { status: 200, headers });
  },
};
