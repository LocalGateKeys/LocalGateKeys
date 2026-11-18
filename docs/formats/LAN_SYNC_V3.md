# LAN sync version 3: sealed hello and commit-then-reveal pairing

Status: format frozen with the vectors in `tests/vectors/sync/lan/v3/` (security scan 2026-11-12, findings
F-02 and F-03 of the LAN sync report).
Reference code: `src/localvault/sync/transport.py` (sealed hello, pin), `src/localvault/sync/pairing.py`
(offer version 2, reveal, code), `src/localvault/sync/lan_sync.py` and `state.py` (the pin in the vault).
Generator: `scripts/make_sync_vectors.py` (`lan_v3_session_files`, `lan_v3_enroll_files`); the Mac host
offer vectors come from `scripts/gen_mac_sync_vectors.py`. lgk-core (Kotlin) and LGKCore (Swift) must pass
the same vectors. Everything not named here is unchanged from protocol version 2 (`docs/SYNC.md`,
"Protocol changes in this version (2026-10-24)", and the `pairing.py` module docstring).

All byte strings below are ASCII. `‖` is concatenation. Base64 is standard with padding. "Canonical
JSON" is `json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))`. Every frame on
the socket is a 4-byte big-endian length followed by its payload.

## 1. Why

- **F-02.** In version 2 the first frame of every Wi-Fi connection is a clear-text signed hello with the
  group id, device id, signing key and exchange key. A device dials the saved addresses of its peers on
  any network, so a host on a foreign network that happens to own such an address learns a stable
  identifier and can track the device. Version 3 encrypts the hello to the responder's pinned exchange
  key, with a fresh key per connection: an outsider sees fixed-size random bytes.
- **F-03.** In version 2 the 6-digit verification code is a hash of values the new device chooses or
  knows from the QR. Someone who saw the QR could grind device ids or keys offline until its request
  shows the same code as the real device. Version 3 mixes in a 32-byte reveal that the inviting device
  commits to in the QR and sends only after the request is fixed.

## 2. Sealed hello (transport protocol version 3)

### 2.1 Inner hello

The inner hello is the version-2 session hello with `"version":3` and the signing label
`localgatekeys|sync|session-hello|v3|`. Same fields, the same counter, nonce and ephemeral X25519 key
rules; `SessionHello.to_bytes()` is its canonical JSON (at most 1022 bytes).

The session key is the version-2 recipe with `v3` in both labels: salt =
SHA-256(`localgatekeys|sync|session-salt|v3|` ‖ sorted hellos), info =
`localgatekeys|sync|session-key|v3|` ‖ session id, IKM = X25519(ephemeral, peer ephemeral) ‖
X25519(static, pinned peer static). Both hellos of one connection must have the same version. The
encrypted frames are unchanged: their metadata keeps `"version":2`.

### 2.2 Sealing

Notation: `S_R` = the responder's 32-byte static exchange public key, as pinned by the initiator for the
peer it means to reach (`require_trusted(peer_id)`); `x_i` / `X_i` = a fresh X25519 key pair for this one
connection (never reused, erased after the handshake).

```
es        = X25519(x_i, S_R)                     # all-zero result: refuse
k_role    = HKDF-SHA256(ikm = es, salt = X_i ‖ S_R,
                        info = "localgatekeys|sync|sealed-hello|v3|" ‖ role, length 32)
            # role = "initiator" or "responder"
aad       = "localgatekeys|sync|sealed-hello|v3|" ‖ X_i
plaintext = u16be(len(inner)) ‖ inner ‖ zero bytes        # exactly 1024 bytes
box       = AES-256-GCM(k_role, nonce = 12 zero bytes, plaintext, aad)   # 1040 bytes with the tag
```

Each key encrypts exactly one message (fresh `X_i` per connection), so the fixed nonce is safe.

- **Initiator first frame:** canonical JSON `{"box":b64(box_initiator),"eph":b64(X_i),"signature":"","version":3}`.
  `signature` is always the empty string: a released version-2 build parses this as a hello of another
  version and answers with its refusal `{"refused":"version","version":2}` instead of closing.
- **Responder answer:** canonical JSON `{"box":b64(box_responder),"version":3}` (same `es`, `aad`; key
  `k_responder`; the inner hello is the responder's version-3 hello for the same session id).

Both frames have a fixed length (the base64 of 1040 bytes plus the fixed JSON), whatever the device ids.

### 2.3 Responder rules, in order

1. A first frame that is an enrollment request is handled as before.
2. A clear-text hello of version 2 from a peer that is **not** pinned (2.5) is answered as in version 2
   (older initiators keep working). From a pinned peer: verify it fully first (signature, group,
   pinned keys, fresh counter); then answer only `{"refused":"version","version":3}` and close. A hello
   that does not verify is closed without an answer.
3. A hello of a version other than 2 or 3 gets `{"refused":"version","version":3}` (unchanged rule).
4. A version-3 first frame must have exactly the keys `box`, `eph`, `signature` (`""`), `version` (3),
   `eph` 32 bytes, `box` 1040 bytes. Compute `es` with the own static exchange key, open `box` with
   `k_initiator`, check the padding (length 1..1022, all padding bytes zero), parse the inner hello
   strictly as version 3, and verify it like a version-2 hello (pinned peer, signature, fresh counter).
   **Anything that fails closes the connection without any answer**, so a non-member, a wrong key or a
   replay learns nothing.
5. Answer with the sealed responder hello, derive the session key, open the first encrypted frame; only
   then count the address as verified and pin the peer (2.5).

### 2.4 Initiator rules

- Never send a clear-text hello. `request` needs the expected peer id (the key to seal to).
- An answer `{"refused":"version","version":N}` means the peer speaks version N: report "peer needs an
  update" (N < 3) or "this device needs an update" (N > 3). Do not retry in clear text.
- Otherwise the answer must be the sealed responder frame (exact keys, 1040-byte box) that opens with
  `k_responder`; its inner hello must be the expected peer's, for the same session id. Pin the peer once
  the encrypted response opens.

### 2.5 The pin (downgrade protection)

A device pins a peer to version 3 the first time a sealed session with it succeeds, in either role, and
when it pairs through a version-2 offer (both sides, at enrollment). The pin is kept in memory
(`SyncState.sealed_peers`) and in the encrypted vault, as the integer field `"hello":3` of the peer's
`lan_peers` entry (absent = not pinned; a reader keeps unknown entry fields). A pin is never removed
except with the peer itself (removal, pairing again). Once pinned, a clear-text hello claiming to be that
peer is refused (2.3, step 2), so an attacker cannot push two updated devices back to the clear hello.

### 2.6 What is left (documented, accepted)

- **Addresses.** A device still dials the saved address of a paired peer on any network (a phone has no
  discovery of its own and a PC may not see the peer's announcement). The sealed frame reveals no
  identifier, but the destination address and port, the timing and the fixed frame size are visible and
  can be linked to the same saved address.
- **Responder confirmation.** A captured sealed first frame that the intended responder never saw (or
  that is replayed after the responder restarted, when its counters start again) gets a sealed answer
  from that responder and silence from anyone else. This tells the replayer only that the host owns the
  key the frame was sealed to; the answer is still encrypted to `es`.
- **Responder secrecy.** The responder's sealed hello is protected by `es`, which a later leak of the
  responder's static exchange key would open (the inner hello holds only public values). The session key
  keeps forward secrecy from the ephemeral exchange.
- **Version probe.** A hello of another version still gets the plain refusal, which shows that the host
  runs LocalGateKeys (version 3), not which device it is.

## 3. Commit-then-reveal pairing (offer version 2, enrollment version 3)

### 3.1 Offer

The inviting device creates a version-2 offer (`OFFER_COMMIT_VERSION`). Random reads, in order: offer id
(uuid4, 16 bytes), transcript nonce (32), pairing secret (32), code (4 bytes at a time, as before), then
the **reveal** (32). The bundle (and so the QR and `public_dict`) gets one more field:

```
"commit": b64(SHA-256("localgatekeys|sync|enroll-commit|v3|" ‖ reveal))      # and "version": 2
```

The reveal itself is never in the bundle, the QR or a log. A version-2 bundle without a 32-byte `commit`
is malformed. A reader ignores a `commit` in a version-1 bundle (the old flow runs); the inviter of a
version-2 offer refuses the old body (3.2), so stripping the version from a QR gains nothing.

### 3.2 Request

For a version-2 offer the enrollment transcript and the request body have `"version":3`; everything else
(fields, encryption, MAC, signature) is as for version 2. For a version-1 offer they keep version 2.
The inviter refuses a body older than the offer takes (version 1, or version 2 for a version-2 offer) with
`update-needed`, before any other check, and sends no reveal.

### 3.3 Reveal frame

Only after a request has decrypted and verified (MAC and signature) and so consumed the offer, the
inviting device sends, on the same connection and before the reply or refusal:

```
"LGKENROLLRV1\n" ‖ canonical JSON {"reveal": b64(reveal)}
```

It is sent at most once per offer: a failed request, a request after the offer was used up and an old
body get no reveal. If the reveal cannot be sent (the connection dropped), the pending request is
declined. The new device checks SHA-256(label ‖ reveal) against `commit` (a mismatch, a second reveal or
a malformed frame aborts), and then reads the usual reply (`LGKENROLLOK1\n` or `LGKENROLLNO1\n`).

### 3.4 Code

```
code = u32be(SHA-256("localgatekeys|sync|enroll-verify|v3|" ‖ transcript ‖ reveal)[0:4]) mod 10^6
```

as 6 ASCII digits. The inviting device shows it with Accept / Decline (it knows the reveal); the new
device shows it only after the reveal checked out. A new device that pairs through a version-2 offer
refuses a reply that came without a matching reveal.

Why this stops grinding: the request (device id, keys, endpoint, name) is fixed and encrypted before the
reveal exists anywhere but the inviting device, and only that one request ever receives it. The holder of
the QR has one try at a 1-in-10^6 code match, and the user compares the codes.

### 3.5 Compatibility

| Inviter | New device | Result |
| --- | --- | --- |
| this version (offer v2) | this version | commit-then-reveal, code v3, both pin the sealed hello |
| this version (offer v2) | released build | the old build sends a version-2 body: `update-needed`, nothing is added |
| released build (offer v1) | this version | version-2 body, code v2 as before, no pin yet (the first sealed sync pins) |

Released parsers ignore unknown bundle keys, so they read the version-2 QR and get the clear
`update-needed` answer.

## 4. Vectors

`tests/vectors/sync/lan/v3/` (README section "LAN protocol version 3"):

- `session.json`: two connections (A initiates, B initiates) with the inner hellos, every sealing value
  (`es`, salt, info, both keys, aad, padded-plaintext hashes, both frames), the session key and one
  request and response; the version-3 refusal. `sealed_hello_initiator.bin`, `sealed_hello_responder.bin`,
  `frame_initiator.bin`, `frame_responder.bin` are the first connection, with the length prefix.
- `qr_payload.txt`, `enroll_request.bin`, `enroll_reveal.bin`, `enroll_reply.bin`, `enroll.json`: one
  commit-then-reveal enrollment of B by A (reveal, commit, transcript, body, reveal frame, code, reply).
- `tests/vectors/sync/mac/host_offer.json`: offers made by `create_pairing_offer` with the five random
  reads of 3.1 (`random_reads_hex`).
- `tests/vectors/sync/lan/session.json` keeps the version-2 connections; its `version_refusal` is what a
  released version-2 responder sends.

Checks a port must make: seal both hellos from the listed private values and compare byte for byte; open
them in both roles; refuse the first connection's frame with the keys of A and C; derive the session key;
open the request and response frames; check the reveal against the commitment, compute the code, open the
reply with the reveal and refuse it without.
