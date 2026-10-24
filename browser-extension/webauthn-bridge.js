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
(() => {
  if (globalThis.__lgkPasskeyBridge) return;
  globalThis.__lgkPasskeyBridge = true;
  const TYPES = new Map([["create", "passkey_create_browser"], ["get", "passkey_get_browser"]]);
  const HELLO = "lgk-passkey-hello", READY = "lgk-passkey-ready";
  let secret = "";

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
    if (typeof data.id !== "string" || !data.id || data.id.length > 64 || !TYPES.has(data.kind)) return;
    const name = `lgk-passkey-res-${secret}`;
    const send = message => {
      try { window.dispatchEvent(new CustomEvent(name, { detail: JSON.stringify(message) })); } catch { /* frame gone */ }
    };
    const reply = result => send({ id: data.id, result });
    const fallback = () => reply({ ok: false, error: "bridge_error" });
    send({ id: data.id, received: true });
    // Transient user activation, read here in the isolated world (the page
    // could lie about it). The broker refuses a create without one, so a page
    // cannot raise the desktop dialog again and again without a click.
    let activation = false;
    try { activation = navigator.userActivation?.isActive === true; } catch { /* not supported */ }
    let sent;
    try {
      sent = api.runtime.sendMessage({ type: TYPES.get(data.kind), origin: location.origin, operation_id: `pk-${data.id}`,
        passkey_protocol: 1, options: data.options, ...(activation ? { user_activation: true } : {}) });
    } catch { fallback(); return; }
    Promise.resolve(sent).then(r => (r && typeof r === "object" ? reply(r) : fallback()), fallback);
  }

  window.addEventListener(HELLO, onHello, true);
  // In case webauthn-page.js ran first: ask it to repeat the hello.
  window.dispatchEvent(new CustomEvent(READY));
})();
