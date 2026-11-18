"use strict";
// Relays passkey requests from webauthn-page.js (the page's MAIN world) to
// the service worker and returns the reply. Runs in the ISOLATED world.
//
// The channel is a pair of CustomEvents named after a secret that
// webauthn-page.js hands over in one hello at document_start, before any
// page script runs. Only the first well-formed hello is taken, then this
// script stops listening for it, so a page can neither replace the secret
// nor address, forge or overhear the channel. Nothing is posted with
// window.postMessage. The service worker still derives the origin and
// document from the browser's sender data and never trusts these fields.
//
// Each well-formed request is confirmed at once with a "received" event, so
// the wrapper can tell a live bridge from one that is gone. A failure here
// (service worker unavailable or a malformed reply) is answered with
// "bridge_error", never "fallback": the wrapper holds only the app's own
// answers to its minimum delay.
//
// Two-step save: the app keeps a created passkey unconfirmed until the page
// reports "confirm" (it is handing the credential to the site) or "discard"
// (it cannot). This bridge forwards one such report per create whose
// credential it handed to the page, and nothing for any other id; it sends
// "discard" itself when a create reply cannot reach the page whole. Neither
// report is answered to the page, so it learns nothing from them.
//
// Document key: every message (create, get, confirm, discard) carries one
// random key drawn here, once per document. Firefox gives the service worker
// no documentId, so it builds the passkey context from the frame id and this
// key: two documents loaded one after the other in one frame never share a
// context, and a confirm or discard names exactly its create's context.
// Chromium's documentId wins over it. The key is drawn here, not shared with
// content.js: that script keeps its own in a closure and runs later, at
// document_idle. Only this extension's own scripts can message the service
// worker, so a page can neither read nor supply the key. No key, no bridge:
// the wrapper then never gets its handshake and uses the browser's WebAuthn.
(() => {
  if (globalThis.__lgkPasskeyBridge) return;
  globalThis.__lgkPasskeyBridge = true;
  let documentKey = "";
  try {
    const seed = crypto.getRandomValues(new Uint8Array(16));
    for (let i = 0; i < seed.length; i++) documentKey += (seed[i] < 16 ? "0" : "") + seed[i].toString(16);
  } catch { return; }
  if (!/^[0-9a-f]{32}$/.test(documentKey)) return;
  const TYPES = new Map([["create", "passkey_create_browser"], ["get", "passkey_get_browser"]]);
  const OUTCOMES = new Map([["confirm", "passkey_confirm_browser"], ["discard", "passkey_discard_browser"]]);
  // Creates whose credential went to the page and still wait for its report.
  const delivered = new Map();
  function report(id, kind) {
    try {
      const sent = api.runtime.sendMessage({ type: OUTCOMES.get(kind), origin: location.origin, operation_id: `pk-${id}`,
        passkey_protocol: 1, document_key: documentKey });
      Promise.resolve(sent).catch(() => {});
    } catch { /* worker unavailable: the app keeps the passkey as an ordinary one after its window */ }
  }
  const HELLO = "lgk-passkey-hello", READY = "lgk-passkey-ready";
  let secret = "";
  // What the page may see of a reply: the error codes webauthn-page.js acts
  // on (any other becomes bridge_error, which it treats the same way) and the
  // credential fields it builds the PublicKeyCredential from. Messages and
  // any other field the app or the service worker adds stay here.
  const ERRORS = new Set(["fallback", "system_provider", "security_error", "user_cancelled", "invalid_state"]);
  const CREDENTIAL_FIELDS = ["credential_id", "client_data_json", "attestation_object", "public_key_spki", "authenticator_data",
    "public_key_algorithm", "transports", "signature", "user_handle", "cred_props_rk"];
  function pageResult(r) {
    if (r.ok === true && r.credential && typeof r.credential === "object") {
      const credential = {};
      for (const key of CREDENTIAL_FIELDS) if (Object.hasOwn(r.credential, key)) credential[key] = r.credential[key];
      return { ok: true, credential };
    }
    return { ok: false, error: typeof r.error === "string" && ERRORS.has(r.error) ? r.error : "bridge_error" };
  }

  function onHello(event) {
    const value = event.detail;
    if (secret || typeof value !== "string" || !/^[0-9a-f]{32}$/.test(value)) return;
    secret = value;
    window.removeEventListener(HELLO, onHello, true);
    window.addEventListener(`lgk-passkey-req-${secret}`, onRequest, true);
    window.dispatchEvent(new CustomEvent(`lgk-passkey-ack-${secret}`));
  }

  function onRequest(event) {
    let data;
    try { data = JSON.parse(event.detail); } catch { return; }
    if (!data || typeof data !== "object") return;
    if (typeof data.id !== "string" || !data.id || data.id.length > 64) return;
    if (OUTCOMES.has(data.kind)) {
      if (delivered.delete(data.id)) report(data.id, data.kind);
      return;
    }
    if (!TYPES.has(data.kind)) return;
    const name = `lgk-passkey-res-${secret}`;
    const send = message => {
      try { window.dispatchEvent(new CustomEvent(name, { detail: JSON.stringify(message) })); return true; } catch { return false; /* frame gone */ }
    };
    const reply = result => send({ id: data.id, result });
    const fallback = () => reply({ ok: false, error: "bridge_error" });
    send({ id: data.id, received: true });
    // Transient user activation, read here in the isolated world (the page
    // could lie about it). The broker refuses a create without one, so a page
    // cannot raise the desktop dialog again and again without a click.
    // An opaque-origin document (sandboxed iframe, CSP sandbox) has the
    // site's URL but is not the site: the browser's own WebAuthn answers it
    // (and refuses). self.origin is the document's real origin ("null").
    // An origin this world cannot read counts as opaque: the page must get an
    // answer now, not wait out its cap.
    let opaque = true;
    try { opaque = self.origin !== location.origin; } catch { /* unknown: the browser answers */ }
    if (opaque) { reply(pageResult({ ok: false, error: "fallback" })); return; }
    let activation = false;
    try { activation = navigator.userActivation?.isActive === true; } catch { /* not supported */ }
    // Permissions policy for a get (known limitation 4): may this frame use
    // publickey-credentials-get? Read here, in the isolated world, where page
    // scripts cannot replace the API. The browser computes it from the
    // embedder's iframe allow attribute and the Permissions-Policy headers.
    // The service worker consults it only for a frame of another site, and
    // only to send a request to the browser: anything but "allowed" does
    // that, never the reverse. Where the API is missing (Firefox without
    // document.featurePolicy) no value is sent, so such frames keep the browser.
    let policy;
    if (data.kind === "get") {
      try {
        const reader = document.permissionsPolicy || document.featurePolicy;
        if (reader && typeof reader.allowsFeature === "function") {
          policy = reader.allowsFeature("publickey-credentials-get") === true ? "allowed" : "denied";
        }
      } catch { policy = undefined; /* unreadable: the browser answers a cross-origin frame */ }
    }
    let sent;
    try {
      sent = api.runtime.sendMessage({ type: TYPES.get(data.kind), origin: location.origin, operation_id: `pk-${data.id}`,
        passkey_protocol: 1, document_key: documentKey, options: data.options, ...(activation ? { user_activation: true } : {}),
        ...(policy ? { publickey_get_policy: policy } : {}) });
    } catch { fallback(); return; }
    Promise.resolve(sent).then(r => {
      if (!r || typeof r !== "object") return fallback();
      const result = pageResult(r);
      if (data.kind !== "create" || r.ok !== true) return reply(result);
      // A created passkey: the page reports what became of it, unless the
      // credential cannot reach it whole, in which case this bridge discards it.
      if (result.ok !== true) { report(data.id, "discard"); return reply(result); }
      delivered.set(data.id, true);
      if (!reply(result) && delivered.delete(data.id)) report(data.id, "discard");
    }, fallback);
  }

  window.addEventListener(HELLO, onHello, true);
  // In case webauthn-page.js ran first: ask it to repeat the hello.
  window.dispatchEvent(new CustomEvent(READY));
})();
