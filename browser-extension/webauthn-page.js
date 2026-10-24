"use strict";
// Passkey wrapper, injected into the page's own JavaScript world (MAIN) at
// document_start so it is in place before the page caches
// navigator.credentials.
//
// It makes no trust decisions: the origin is derived from the browser's
// sender data by the service worker, and the LocalGateKeys app builds
// clientDataJSON from that origin and asks the user.
//
// Fingerprinting and probing (audit 2026-10-18, Low):
// * create/get replace the originals on CredentialsContainer.prototype with
//   the same property attributes, name and length, no prototype property,
//   and a Function.prototype.toString that reports native code for them.
//   navigator.credentials keeps no own properties.
// * The channel to webauthn-bridge.js (ISOLATED world) is a pair of
//   CustomEvents named after a 128-bit secret. The secret goes to the bridge
//   in one handshake at document_start, before any page script has run: the
//   bridge takes the first hello only and then stops listening, and this
//   script stops answering once the bridge acknowledged. A page cannot
//   address, forge or overhear the channel, and no window message is posted.
// * An answer from the LocalGateKeys app that could reveal vault state
//   (fallback: locked, no passkey here, cooldown; cancel; existing passkey)
//   is held back to a minimum, slightly jittered delay from the call, so
//   "locked" or "no passkey here" is not a fast, silent answer that differs
//   from a user dismissing the prompt. Nothing else is held: an unreachable
//   app or native host, a bridge or service-worker error and a missing ack
//   reveal nothing about the vault and go to the browser at once. The floor
//   never starts once 1.5 s have passed, never holds past 2.5 s from the
//   call, and is skipped in cross-origin frames, so the browser's own
//   create() still runs well inside the transient user activation window.
// Residual: a script can still compare with a pristine toString from a
// fresh iframe, see this file in an error stack, or patch built-in
// prototype methods (String/Array) to watch a call pass through. That shows
// the extension is installed, not what the vault holds.
//
// Every reply other than success, an explicit cancel, an invalid state or a
// security error hands the original options to the browser's own
// authenticator, so a missing app or an older bridge never breaks sign-in.
(() => {
  // Built-ins are captured before any page script can replace them.
  const apply = Reflect.apply;
  const defineProperty = Object.defineProperty;
  const getOwnPropertyDescriptor = Object.getOwnPropertyDescriptor;
  const objectCreate = Object.create;
  const objectEntries = Object.entries;
  const isArray = Array.isArray;
  const isView = ArrayBuffer.isView;
  const ArrayBufferCtor = ArrayBuffer;
  const Uint8ArrayCtor = Uint8Array;
  const PromiseCtor = Promise;
  const DOMExceptionCtor = DOMException;
  const TypeErrorCtor = TypeError;
  const CustomEventCtor = CustomEvent;
  const WeakMapCtor = WeakMap;
  const MapCtor = Map;
  const mapGet = Map.prototype.get, mapSet = Map.prototype.set, mapDelete = Map.prototype.delete;
  const weakGet = WeakMap.prototype.get, weakSet = WeakMap.prototype.set;
  const fromCharCode = String.fromCharCode;
  const jsonStringify = JSON.stringify, jsonParse = JSON.parse;
  const toBase64 = btoa, fromBase64 = atob;
  const setTimer = setTimeout;
  const clearTimer = clearTimeout;
  const addListener = EventTarget.prototype.addEventListener;
  const removeListener = EventTarget.prototype.removeEventListener;
  const dispatch = EventTarget.prototype.dispatchEvent;
  const randomValues = crypto.getRandomValues.bind(crypto);
  const clock = typeof performance === "object" && performance && typeof performance.now === "function"
    ? performance.now.bind(performance) : Date.now;
  const fnToString = Function.prototype.toString;
  const view = window;

  // ---- Secret channel to the ISOLATED bridge. Set up first, even where
  // there is nothing to wrap, so the bridge never waits for a hello that a
  // page script could send instead.
  const HELLO = "lgk-passkey-hello", READY = "lgk-passkey-ready";
  const seed = randomValues(new Uint8ArrayCtor(16));
  let secret = "";
  for (let i = 0; i < seed.length; i++) secret += (seed[i] < 16 ? "0" : "") + seed[i].toString(16);
  const ACK = `lgk-passkey-ack-${secret}`, REQ = `lgk-passkey-req-${secret}`, RES = `lgk-passkey-res-${secret}`;
  const fire = (type, detail) => apply(dispatch, view, [new CustomEventCtor(type, { detail })]);
  let acknowledged = false;
  const onAck = () => {
    acknowledged = true;
    apply(removeListener, view, [READY, onReady, true]);
    apply(removeListener, view, [ACK, onAck, true]);
  };
  // The bridge may run before or after this script; whichever runs second
  // completes the handshake, both still before any page script.
  const onReady = () => { if (!acknowledged) fire(HELLO, secret); };
  apply(addListener, view, [ACK, onAck, true]);
  apply(addListener, view, [READY, onReady, true]);
  fire(HELLO, secret);

  // A cross-origin frame (the top window is unreadable or another origin)
  // gets no floor. `top` is unforgeable; any throw counts as cross-origin.
  let crossOriginFrame = true;
  try {
    const top = view.top;
    crossOriginFrame = !(top === null || top === undefined || top === view || top.location.origin === view.location.origin);
  } catch { /* cross-origin */ }

  const credentials = navigator.credentials;
  if (!credentials || typeof credentials.create !== "function" || typeof credentials.get !== "function") return;
  // Wrap where the originals live (CredentialsContainer.prototype), with the
  // same attributes, so the object gains no own properties.
  const proto = typeof CredentialsContainer === "function" && CredentialsContainer.prototype;
  const holder = proto && getOwnPropertyDescriptor(proto, "create") && getOwnPropertyDescriptor(proto, "get") ? proto : credentials;
  const createDescriptor = getOwnPropertyDescriptor(holder, "create");
  const getDescriptor = getOwnPropertyDescriptor(holder, "get");
  if (!createDescriptor || !getDescriptor || typeof createDescriptor.value !== "function" || typeof getDescriptor.value !== "function") return;
  const rawCreate = createDescriptor.value;
  const rawGet = getDescriptor.value;
  const pending = new MapCtor();
  let sequence = 0;

  apply(addListener, view, [RES, event => {
    let data;
    try { data = jsonParse(event.detail); } catch { return; }
    if (!data || typeof data !== "object" || typeof data.id !== "string") return;
    const entry = apply(mapGet, pending, [data.id]);
    if (!entry) return;
    // The bridge confirms it took the request before asking the worker.
    if (data.received === true) entry.received();
    else entry.settle(data.result);
  }, true]);

  function bytesOf(value) {
    if (value instanceof ArrayBufferCtor) return new Uint8ArrayCtor(value);
    if (isView(value)) return new Uint8ArrayCtor(value.buffer, value.byteOffset, value.byteLength);
    throw new TypeErrorCtor("Expected a BufferSource");
  }
  function encode(value) {
    const bytes = bytesOf(value);
    let binary = "";
    for (let i = 0; i < bytes.length; i++) binary += fromCharCode(bytes[i]);
    return toBase64(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function decode(text) {
    if (typeof text !== "string") throw new TypeErrorCtor("Expected base64url text");
    const binary = fromBase64(text.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((text.length + 3) % 4));
    const bytes = new Uint8ArrayCtor(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  const text = value => (typeof value === "string" ? value : undefined);
  const descriptors = list => (isArray(list) ? list.map(d => ({ type: text(d && d.type) || "public-key", id: encode(d.id) })) : undefined);

  function serializeCreate(pk) {
    const rp = pk.rp || {}, user = pk.user || {};
    return {
      rp: { id: text(rp.id), name: text(rp.name) },
      user: { id: encode(user.id), name: text(user.name), displayName: text(user.displayName) },
      challenge: encode(pk.challenge),
      pubKeyCredParams: isArray(pk.pubKeyCredParams)
        ? pk.pubKeyCredParams.map(p => ({ type: text(p && p.type), alg: typeof (p && p.alg) === "number" ? p.alg : undefined }))
        : [],
      excludeCredentials: descriptors(pk.excludeCredentials),
      authenticatorSelection: { userVerification: text(pk.authenticatorSelection && pk.authenticatorSelection.userVerification) },
      extensions: { credProps: !!(pk.extensions && pk.extensions.credProps === true) },
    };
  }
  function serializeGet(pk) {
    return {
      rpId: text(pk.rpId),
      challenge: encode(pk.challenge),
      allowCredentials: descriptors(pk.allowCredentials),
      userVerification: text(pk.userVerification),
    };
  }

  function abortError(signal) {
    return signal && signal.reason !== undefined ? signal.reason : new DOMExceptionCtor("The operation was aborted.", "AbortError");
  }
  function onAbort(signal, run) {
    if (signal) apply(addListener, signal, ["abort", run, { once: true }]);
  }
  // No "received" from the bridge within ACK_MS (it is gone, for example
  // after document.open() removed its listeners) or no reply within CAP_MS:
  // the request goes to the browser. The service worker gives up at 90 s.
  // Transient user activation (getter captured now; absent in older engines).
  const userActivation = navigator.userActivation;
  const activationGetter = typeof UserActivation === "function" ? getOwnPropertyDescriptor(UserActivation.prototype, "isActive")?.get : undefined;
  // null: the engine has no navigator.userActivation (the bridge then reports
  // no activation and the app answers fallback).
  function activated() {
    if (!userActivation || typeof activationGetter !== "function") return null;
    try { return apply(activationGetter, userActivation, []) === true; } catch { return false; }
  }
  const ACK_MS = 1000, CAP_MS = 120000;
  const UNREACHABLE = "unreachable";
  function relay(kind, options, signal) {
    return new PromiseCtor((resolve, reject) => {
      const nonce = randomValues(new Uint8ArrayCtor(6));
      let id = (sequence++).toString(36) + "-";
      for (let i = 0; i < nonce.length; i++) id += (nonce[i] < 16 ? "0" : "") + nonce[i].toString(16);
      let ackTimer, capTimer;
      const finish = () => {
        if (!apply(mapDelete, pending, [id])) return false;
        clearTimer(ackTimer); clearTimer(capTimer);
        return true;
      };
      const settle = result => { if (finish()) resolve(result); };
      apply(mapSet, pending, [id, { settle, received: () => clearTimer(ackTimer) }]);
      onAbort(signal, () => { if (finish()) reject(abortError(signal)); });
      ackTimer = setTimer(() => settle({ ok: false, error: UNREACHABLE }), ACK_MS);
      capTimer = setTimer(() => settle({ ok: false, error: UNREACHABLE }), CAP_MS);
      try {
        fire(REQ, jsonStringify({ id, kind, options }));
      } catch {
        settle({ ok: false, error: UNREACHABLE });
      }
    });
  }

  // A prompt the user dismisses takes at least this long; the app's own
  // locked, "no passkey here" and cooldown answers are held back to it too.
  // These are the only codes the app (passkey_broker.py) answers with short
  // of success and security_error; transport and bridge failures carry
  // other codes and are never held.
  const FLOORED = new MapCtor([["fallback", true], ["user_cancelled", true], ["invalid_state", true]]);
  const FLOOR_MS = 900, JITTER_MS = 700, FLOOR_START_LIMIT_MS = 1500, HOLD_LIMIT_MS = 2500;
  function floor(started, signal) {
    const elapsed = clock() - started;
    if (!(elapsed >= 0) || elapsed > FLOOR_START_LIMIT_MS) return undefined;
    const jitter = randomValues(new Uint8ArrayCtor(1))[0] / 255 * JITTER_MS;
    const target = FLOOR_MS + jitter < HOLD_LIMIT_MS ? FLOOR_MS + jitter : HOLD_LIMIT_MS;
    const wait = started + target - clock();
    if (!(wait > 0)) return undefined;
    return new PromiseCtor((resolve, reject) => {
      setTimer(resolve, wait);
      onAbort(signal, () => reject(abortError(signal)));
    });
  }

  function define(object, values) {
    for (const [key, value] of objectEntries(values)) {
      defineProperty(object, key, { value, enumerable: true, configurable: true });
    }
    return object;
  }
  function prototypeOf(name) {
    const cls = globalThis[name];
    return cls && cls.prototype ? cls.prototype : Object.prototype;
  }
  function build(kind, c, credProps) {
    const extensions = kind === "create" && credProps ? { credProps: { rk: c.cred_props_rk === true } } : {};
    const response = objectCreate(prototypeOf(kind === "create" ? "AuthenticatorAttestationResponse" : "AuthenticatorAssertionResponse"));
    let responseJSON;
    if (kind === "create") {
      const transports = isArray(c.transports) ? c.transports.filter(t => typeof t === "string") : [];
      decode(c.attestation_object); decode(c.public_key_spki); decode(c.authenticator_data);
      define(response, {
        clientDataJSON: decode(c.client_data_json),
        attestationObject: decode(c.attestation_object),
        getTransports: () => [...transports],
        getAuthenticatorData: () => decode(c.authenticator_data),
        getPublicKey: () => decode(c.public_key_spki),
        getPublicKeyAlgorithm: () => c.public_key_algorithm,
      });
      responseJSON = { clientDataJSON: c.client_data_json, attestationObject: c.attestation_object,
        authenticatorData: c.authenticator_data, transports: [...transports], publicKey: c.public_key_spki,
        publicKeyAlgorithm: c.public_key_algorithm };
    } else {
      define(response, {
        clientDataJSON: decode(c.client_data_json),
        authenticatorData: decode(c.authenticator_data),
        signature: decode(c.signature),
        userHandle: c.user_handle ? decode(c.user_handle) : null,
      });
      responseJSON = { clientDataJSON: c.client_data_json, authenticatorData: c.authenticator_data,
        signature: c.signature, userHandle: c.user_handle || null };
    }
    const credential = objectCreate(prototypeOf("PublicKeyCredential"));
    return define(credential, {
      id: c.credential_id,
      rawId: decode(c.credential_id),
      type: "public-key",
      authenticatorAttachment: "platform",
      response,
      getClientExtensionResults: () => jsonParse(jsonStringify(extensions)),
      toJSON: () => ({ id: c.credential_id, rawId: c.credential_id, type: "public-key",
        authenticatorAttachment: "platform", clientExtensionResults: jsonParse(jsonStringify(extensions)),
        response: { ...responseJSON } }),
    });
  }

  async function handle(kind, options, original) {
    const pk = options && typeof options === "object" ? options.publicKey : undefined;
    // Conditional mediation (autofill UI, conditional create) and a bridge
    // that never acknowledged the handshake go straight to the browser.
    if (!pk || typeof pk !== "object" || options.mediation === "conditional" || !window.isSecureContext || !acknowledged) {
      return original(options);
    }
    // Registration without a click or key press goes to the browser: the
    // LocalGateKeys dialog is raised only for a user-initiated create. The
    // bridge reads the activation again in its own world and the app enforces it.
    if (kind === "create" && activated() === false) return original(options);
    const signal = options.signal;
    if (signal && signal.aborted) throw abortError(signal);
    let serialized;
    try { serialized = kind === "create" ? serializeCreate(pk) : serializeGet(pk); } catch { return original(options); }
    const started = clock();
    const result = await relay(kind, serialized, signal);
    if (result && result.ok === true && result.credential && typeof result.credential === "object") {
      try { return build(kind, result.credential, kind === "create" && serialized.extensions.credProps); } catch { /* falls back below */ }
    }
    const error = result && result.error;
    if (error === "security_error") throw new DOMExceptionCtor("The relying party ID is not valid for this page.", "SecurityError");
    if (typeof error === "string" && apply(mapGet, FLOORED, [error]) === true && !crossOriginFrame) await floor(started, signal);
    if (error === "user_cancelled") throw new DOMExceptionCtor("The operation either timed out or was not allowed.", "NotAllowedError");
    if (error === "invalid_state") throw new DOMExceptionCtor("This account already has a passkey on this site.", "InvalidStateError");
    return original(options);
  }

  // Method shorthand: like the natives, no prototype property, not a
  // constructor, length 0. Called on anything but navigator.credentials they
  // behave exactly as the originals (including their errors).
  const wrappers = new WeakMapCtor();
  const methods = {
    create() {
      if (this !== credentials) return apply(rawCreate, this, arguments);
      return handle("create", arguments[0], options => apply(rawCreate, credentials, [options]));
    },
    get() {
      if (this !== credentials) return apply(rawGet, this, arguments);
      return handle("get", arguments[0], options => apply(rawGet, credentials, [options]));
    },
    toString() {
      const native = apply(weakGet, wrappers, [this]);
      return apply(fnToString, native === undefined ? this : native, arguments);
    },
  };
  apply(weakSet, wrappers, [methods.create, rawCreate]);
  apply(weakSet, wrappers, [methods.get, rawGet]);
  apply(weakSet, wrappers, [methods.toString, fnToString]);
  const toStringDescriptor = getOwnPropertyDescriptor(Function.prototype, "toString");
  if (toStringDescriptor && toStringDescriptor.value === fnToString) {
    defineProperty(Function.prototype, "toString", { ...toStringDescriptor, value: methods.toString });
  }
  defineProperty(holder, "create", { ...createDescriptor, value: methods.create });
  defineProperty(holder, "get", { ...getDescriptor, value: methods.get });
})();
