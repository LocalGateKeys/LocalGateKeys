package app.localgatekeys.core.lan

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.FixedRandom
import app.localgatekeys.core.support.MemoryCounterStore
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.Vectors
import java.io.File
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/** Port of the session, frame, message, hello-counter and client parts of Swift `LanTests`. */
class LanSessionTest {
    private val groupId = "5b0c7d3e-9a41-4f6b-8c2d-3e1a7f905b64"

    private fun obj(v: JsonValue?): Map<String, JsonValue> = (v as? JsonValue.Obj)?.fields ?: emptyMap()
    private fun arr(v: JsonValue?): List<JsonValue> = (v as? JsonValue.Arr)?.items ?: emptyList()
    private fun str(v: JsonValue?): String = (v as? JsonValue.Str)?.v ?: ""
    private fun bytes(s: String): ByteArray = s.toByteArray(Charsets.UTF_8)
    private fun lanFile(name: String): File = Vectors.sync("lan/$name")
    private fun vec(name: String): Map<String, JsonValue> = obj(Vectors.json(lanFile(name)))
    private fun lanBytes(name: String): ByteArray = lanFile(name).readBytes()
    private fun sha(b: ByteArray): String = Vectors.hexString(MessageDigest.getInstance("SHA-256").digest(b))
    private fun canon(m: Map<String, JsonValue>): ByteArray = CanonicalJson.encode(JsonValue.Obj(m), Dialect.ASCII)

    private fun identity(who: String): DeviceIdentity {
        val ids = obj(Vectors.json(Vectors.sync("identities.json")).obj().fields["devices"])
        val p = obj(obj(ids[who])["private"])
        return DeviceIdentity(
            str(p["device_id"]),
            Base64Std.decodeStrict(str(p["signing_private"])),
            Base64Std.decodeStrict(str(p["exchange_private"])),
        )
    }

    private fun pinned(who: String): PinnedPeer {
        val i = identity(who)
        return PinnedPeer(i.deviceId, groupId, i.signingPublicKey, i.exchangePublicKey, null)
    }

    private fun groupKey(): GroupKey = GroupKey(groupId, 1, Vectors.hex(str(obj(vec("expected_lan.json")["reply"])["key_hex"])))

    private fun transportKind(block: () -> Unit): Pair<LanTransportException.Kind, String> {
        val e = assertFailsWith<LanTransportException> { block() }
        return e.kind to e.detail
    }

    private fun syncReason(block: () -> Unit): String = assertFailsWith<LanSyncException> { block() }.reason

    // ---- session handshake ----

    /** Checks one recorded connection (session.json or messages.json entry) and returns its key. */
    private fun checkConnection(s: Map<String, JsonValue>): ByteArray {
        val hello = obj(s["hello"])
        val ini = obj(hello["initiator"])
        val res = obj(hello["responder"])
        val iniId = identity(str(ini["device"]))
        val resId = identity(str(res["device"]))
        val hi = SessionHello.parse(bytes(str(ini["text"])))
        val hr = SessionHello.parse(bytes(str(res["text"])))
        assertContentEquals(bytes(str(ini["text"])), hi.toBytes())
        assertContentEquals(bytes(str(res["text"])), hr.toBytes())
        assertEquals(str(ini["signing_input_hex"]), Vectors.hexString(hi.signingBytes()))
        assertEquals(str(res["signing_input_hex"]), Vectors.hexString(hr.signingBytes()))
        assertEquals((ini["counter"] as JsonValue.Int).v, hi.counter)
        SessionHello.verify(hi, pinned(str(ini["device"])), groupId)
        SessionHello.verify(hr, pinned(str(res["device"])), groupId)
        val sid = Vectors.hex(str(s["session_id"]))
        assertContentEquals(sid, hi.sessionId)
        assertContentEquals(sid, hr.sessionId)
        val transcript = SecureChannel.transcript(hi.toBytes(), hr.toBytes())
        assertEquals(str(s["transcript_sorted_hex"]), Vectors.hexString(transcript))
        val hiBytes = hi.toBytes()
        val startsWithInitiator = transcript.size >= hiBytes.size && hiBytes.indices.all { transcript[it] == hiBytes[it] }
        assertEquals(str(s["sorted_first"]), if (startsWithInitiator) "initiator" else "responder")
        val shared = iniId.exchange(resId.exchangePublicKey)
        assertEquals(str(s["shared_secret_hex"]), Vectors.hexString(shared))
        assertEquals(str(s["salt"]), Vectors.hexString(SecureChannel.salt(transcript)))
        assertEquals(str(s["info_hex"]), Vectors.hexString(SecureChannel.info(sid)))
        val key = SecureChannel.deriveKey(shared, sid, transcript)
        assertEquals(str(s["key"]), Vectors.hexString(key))
        assertEquals(str(s["prefix_initiator"]), Vectors.hexString(SecureChannel.prefix(key, SecureChannel.Role.INITIATOR)))
        assertEquals(str(s["prefix_responder"]), Vectors.hexString(SecureChannel.prefix(key, SecureChannel.Role.RESPONDER)))
        // Both sides derive the same key from the recorded hellos.
        val ci = SecureChannel(iniId, pinned(str(res["device"])), groupId, sid, SecureChannel.Role.INITIATOR, hi, hr)
        val cr = SecureChannel(resId, pinned(str(ini["device"])), groupId, sid, SecureChannel.Role.RESPONDER, hr, hi)
        assertContentEquals(key, ci.key)
        assertContentEquals(key, cr.key)
        return key
    }

    /** Seals [plain] as [role] with a fresh channel and requires the recorded frame bytes; opens them back. */
    private fun checkFrame(
        key: ByteArray,
        sid: ByteArray,
        role: SecureChannel.Role,
        plain: ByteArray,
        frame: ByteArray,
        entry: Map<String, JsonValue>,
    ) {
        val other = if (role == SecureChannel.Role.INITIATOR) SecureChannel.Role.RESPONDER else SecureChannel.Role.INITIATOR
        val sender = SecureChannel(key, sid, role)
        val receiver = SecureChannel(key, sid, other)
        assertContentEquals(frame, sender.seal(plain))
        assertContentEquals(plain, receiver.open(frame))
        assertEquals(
            LanTransportException.Kind.REPLAY to "Duplicate or out-of-order encrypted frame",
            transportKind { receiver.open(frame) },
        )
        val outer = SecureChannel.parseFrame(LanTransport.decodeFrame(frame))
        val meta = outer - "ciphertext"
        assertContentEquals(bytes(str(entry["aad"])), canon(meta))
        assertEquals(str(entry["nonce"]), Vectors.hexString(Base64Std.decodeStrict(str(outer["nonce"]))))
        assertEquals(str(entry["frame_sha256"]), sha(frame))
        assertEquals(str(entry["plaintext_sha256"]), sha(plain))
    }

    @Test
    fun session_json_connections() {
        val sessions = arr(vec("session.json")["sessions"])
        assertEquals(3, sessions.size)
        for ((n, sv) in sessions.withIndex()) {
            val s = obj(sv)
            val key = checkConnection(s)
            val sid = Vectors.hex(str(s["session_id"]))
            for ((role, name) in listOf(SecureChannel.Role.INITIATOR to "request", SecureChannel.Role.RESPONDER to "response")) {
                val e = obj(s[name])
                checkFrame(key, sid, role, bytes(str(e["plaintext"])), Vectors.hex(str(e["frame_hex"])), e)
            }
            if (n == 0) {
                val h = obj(s["hello"])
                assertContentEquals(lanBytes("hello_initiator.bin"), LanTransport.encodeFrame(bytes(str(obj(h["initiator"])["text"]))))
                assertContentEquals(lanBytes("hello_responder.bin"), LanTransport.encodeFrame(bytes(str(obj(h["responder"])["text"]))))
                assertContentEquals(lanBytes("frame_initiator.bin"), Vectors.hex(str(obj(s["request"])["frame_hex"])))
                assertContentEquals(lanBytes("frame_responder.bin"), Vectors.hex(str(obj(s["response"])["frame_hex"])))
            }
        }
    }

    @Test
    fun hello_matches_vector_exactly() {
        // Swift can only compare "except signature" (hedged Ed25519); Ed25519 here is deterministic, so the
        // whole hello, signature included, must equal the recorded bytes.
        val s = obj(arr(vec("session.json")["sessions"])[2]) // counters 9 and 10
        val ini = obj(obj(s["hello"])["initiator"])
        val recorded = SessionHello.parse(bytes(str(ini["text"])))
        val mine = SessionHello.make(
            identity("A"), groupId, Vectors.hex(str(s["session_id"])), 9,
            QueueRandom(listOf(Vectors.hex(str(ini["nonce_hex"])))),
        )
        assertContentEquals(Vectors.hex(str(ini["signing_input_hex"])), mine.signingBytes())
        assertEquals(recorded.unsignedJson, mine.unsignedJson)
        assertContentEquals(bytes(str(ini["text"])), mine.toBytes())
        assertEquals(recorded, mine)
        SessionHello.verify(mine, pinned("A"), groupId)
        assertEquals(LanTransportException.Kind.AUTHENTICATION, transportKind { SessionHello.verify(mine, pinned("B"), groupId) }.first)
        val wrongExchange = PinnedPeer(mine.deviceId, groupId, mine.signingPublic, identity("B").exchangePublicKey, null)
        assertEquals(
            "Session exchange key is not pinned",
            transportKind { SessionHello.verify(mine, wrongExchange, groupId) }.second,
        )
        assertEquals("Session group mismatch", transportKind { SessionHello.verify(recorded, pinned("A"), "other-group") }.second)
        // make refuses malformed input.
        assertEquals(
            "Session hello input is malformed",
            transportKind { SessionHello.make(identity("A"), groupId, ByteArray(15), 1, FixedRandom(ByteArray(32))) }.second,
        )
        assertEquals(
            "Session hello input is malformed",
            transportKind { SessionHello.make(identity("A"), groupId, ByteArray(16), -1, FixedRandom(ByteArray(32))) }.second,
        )
    }

    @Test
    fun hello_and_frame_parsers_are_strict() {
        val s = obj(arr(vec("session.json")["sessions"])[0])
        val hello = obj(CanonicalJson.parse(bytes(str(obj(obj(s["hello"])["initiator"])["text"]))))
        val frame = SecureChannel.parseFrame(LanTransport.decodeFrame(Vectors.hex(str(obj(s["request"])["frame_hex"]))))

        fun variants(o: Map<String, JsonValue>): List<ByteArray> {
            val out = ArrayList<ByteArray>()
            out.add(canon(o + ("extra" to JsonValue.Int(1))))
            for (k in o.keys) out.add(canon(o - k))
            for (v in listOf(JsonValue.Bool(true), JsonValue.Float(1.0), JsonValue.Str("1"), JsonValue.Int(2))) {
                out.add(canon(o + ("version" to v)))
            }
            val text = String(canon(o), Charsets.UTF_8)
            out.add(bytes(text.dropLast(1) + ",\"version\":1}")) // duplicate key
            return out
        }
        SessionHello.parse(canon(hello))
        for (v in variants(hello)) {
            assertFailsWith<LanTransportException>(String(v, Charsets.UTF_8)) { SessionHello.parse(v) }
        }
        for (v in variants(frame)) {
            assertFailsWith<LanTransportException>(String(v, Charsets.UTF_8)) { SecureChannel.parseFrame(v) }
        }
        assertFailsWith<LanTransportException> { SessionHello.parse(canon(hello + ("counter" to JsonValue.Int(-1)))) }
        assertFailsWith<LanTransportException> {
            SessionHello.parse(canon(hello + ("nonce" to JsonValue.Str(Base64Std.encode(byteArrayOf(1, 2, 3))))))
        }
        assertFailsWith<LanTransportException> { LanTransport.decodeFrame(byteArrayOf(0, 0, 0, 2, 1)) }
        // Frame bounds.
        assertEquals(LanTransportException.Kind.TOO_LARGE, transportKind { LanTransport.encodeFrame(ByteArray(0)) }.first)
        assertEquals(LanTransportException.Kind.TOO_LARGE, transportKind { LanTransport.decodeFrame(byteArrayOf(0, 0, 0, 0)) }.first)
        assertEquals(LanTransportException.Kind.MALFORMED, transportKind { LanTransport.decodeFrame(byteArrayOf(0, 0)) }.first)
    }

    // ---- messages ----

    private fun messagePlain(conn: Map<String, JsonValue>, role: String, key: ByteArray): ByteArray {
        val e = obj(conn[role])
        val frame = lanBytes(str(e["file"]))
        val ch = SecureChannel(
            key, Vectors.hex(str(conn["session_id"])),
            if (role == "request") SecureChannel.Role.RESPONDER else SecureChannel.Role.INITIATOR,
        )
        val plain = ch.open(frame)
        val p = e["plaintext"]
        if (p is JsonValue.Str) assertContentEquals(bytes(p.v), plain)
        return plain
    }

    @Test
    fun messages_json_frames_and_views() {
        val m = vec("messages.json")
        val gk = groupKey()
        val conns = arr(m["connections"]).map { obj(it) }
        assertEquals(3, conns.size)
        val viewA = java.io.ByteArrayOutputStream()
        val viewB = java.io.ByteArrayOutputStream()
        for (c in conns) {
            val key = checkConnection(c)
            val sid = Vectors.hex(str(c["session_id"]))
            for ((role, name) in listOf(SecureChannel.Role.INITIATOR to "request", SecureChannel.Role.RESPONDER to "response")) {
                val e = obj(c[name])
                val plain = messagePlain(c, name, key)
                assertEquals((e["plaintext_size"] as JsonValue.Int).v.toInt(), plain.size)
                checkFrame(key, sid, role, plain, lanBytes(str(e["file"])), e)
                val msg = LanMessages.parse(plain)
                assertContentEquals(plain, LanMessages.encode(msg))
                if (msg is LanMessage.View) {
                    if (msg.transfer == str(obj(obj(m["views"])["initiator"])["transfer"])) {
                        viewA.write(Base64Std.decodeStrict(msg.view))
                    } else {
                        viewB.write(Base64Std.decodeStrict(msg.view))
                    }
                }
            }
        }
        for ((raw, who, dev) in listOf(Triple(viewA.toByteArray(), "initiator", "A"), Triple(viewB.toByteArray(), "responder", "B"))) {
            val info = obj(obj(m["views"])[who])
            assertEquals(str(info["sha256"]), sha(raw))
            assertEquals(arr(info["chunk_sizes"]).map { (it as JsonValue.Int).v.toInt() }, LanMessages.splitView(raw).map { it.size })
            val decoded = ViewFile.decode(raw, gk, identity(dev).deviceId)
            assertEquals(20, decoded.second.size)
        }
        val errors = arr(m["errors"]).map { obj(it) }
        assertEquals(LanMessages.errorReasons, errors.map { str(it["reason"]) })
        for (e in errors) {
            assertContentEquals(bytes(str(e["plaintext"])), LanMessages.encode(LanMessage.Error(str(e["reason"]))))
        }
    }

    @Test
    fun message_parser_rejects_bad_shapes() {
        val t = "a".repeat(32)
        val ok = """{"seq":0,"transfer":"$t","type":"ack"}"""
        assertEquals(LanMessage.Ack(t, 0), LanMessages.parse(bytes(ok)))
        val bads = listOf(
            """{"seq":0,"transfer":"$t","type":"ack","x":1}""",
            """{"seq":0,"type":"ack"}""",
            """{"seq":0.0,"transfer":"$t","type":"ack"}""",
            """{"seq":0,"transfer":"${t.uppercase()}","type":"ack"}""",
            """{"seq":0,"transfer":"$t","type":"ack","seq":0}""",
            """{"reason":"","type":"error"}""",
            """{"type":"hello"}""",
            """{"epoch":1,"group_id":"g","seq":1,"size":5,"total":1,"transfer":"$t","type":"view","view":"AA=="}""",
        )
        for (bad in bads) assertEquals("bad-message", syncReason { LanMessages.parse(bytes(bad)) }, bad)
        assertEquals(
            "too-large",
            syncReason {
                LanMessages.parse(
                    bytes("""{"epoch":1,"group_id":"g","seq":0,"size":67108865,"total":1,"transfer":"$t","type":"view","view":"AA=="}"""),
                )
            },
        )
    }

    // ---- hello counters ----

    @Test
    fun hello_counters_come_from_persisted_blocks_and_never_repeat() {
        val store = MemoryCounterStore()
        val src = HelloCounterSource(store, FixedClock(10))
        assertEquals(10_000_000L, src.nextCounter())
        assertEquals(listOf(10_000_063L), store.saves) // saved before the first value is used
        for (i in 1 until 64) src.nextCounter()
        assertEquals(1, store.saves.size)
        assertEquals(10_000_064L, src.nextCounter())
        assertEquals(listOf(10_000_063L, 10_000_127L), store.saves)
        // Restart with the clock set backwards: continues above the persisted block.
        val again = HelloCounterSource(store, FixedClock(1))
        assertEquals(10_000_128L, again.nextCounter())
        // Inbound: must increase per peer.
        again.acceptInbound(5, "p")
        assertFailsWith<LanTransportException> { again.acceptInbound(5, "p") }
        assertFailsWith<LanTransportException> { again.acceptInbound(4, "p") }
        again.acceptInbound(6, "p")
        again.acceptInbound(1, "q")
        // Exhaustion is refused, never wrapped.
        val full = MemoryCounterStore().also { it.hello = Long.MAX_VALUE }
        assertEquals(
            LanTransportException.Kind.REPLAY to "Outbound sync counter is exhausted",
            transportKind { HelloCounterSource(full, FixedClock(0)).nextCounter() },
        )
    }

    // ---- client ----

    /**
     * A test-side responder holding B's identity (what the Swift test's live responder does): checks the
     * client's hello, answers with a hello of [counter] (and the recorded nonce when given), opens the
     * request and seals `answer(request)`. `exchange` is synchronous, so no threads are needed.
     */
    private inner class FakeConnection(
        val b: DeviceIdentity,
        val pinnedA: PinnedPeer,
        val counter: Long,
        val nonce: ByteArray?,
        val answer: (ByteArray) -> ByteArray,
    ) : LanConnection {
        var clientHello: SessionHello? = null
        var localHello: SessionHello? = null
        var channel: SecureChannel? = null

        override fun exchange(frame: ByteArray): ByteArray {
            val ch = channel
            if (ch == null) {
                val h = SessionHello.parse(LanTransport.decodeFrame(frame))
                SessionHello.verify(h, pinnedA, groupId)
                val mine = SessionHello.make(b, groupId, h.sessionId, counter, FixedRandom(nonce ?: SystemRandomSource().bytes(32)))
                clientHello = h
                localHello = mine
                channel = SecureChannel(b, pinnedA, groupId, h.sessionId, SecureChannel.Role.RESPONDER, mine, h)
                return LanTransport.encodeFrame(mine.toBytes())
            }
            val request = ch.open(frame)
            return ch.seal(answer(request))
        }
    }

    private inner class FakeConnector(val make: (Int) -> FakeConnection) : LanConnector {
        val opened = ArrayList<FakeConnection>()

        override fun connect(peer: PinnedPeer): LanConnection {
            val c = make(opened.size)
            opened.add(c)
            return c
        }
    }

    @Test
    fun client_against_recorded_exchange() {
        // Each messages.json connection through the client's per-connection step with a fresh counter
        // store (the recorded hellos all carry counter 1). Where Swift compares "except signature", the
        // deterministic Ed25519 here lets both hellos be compared byte for byte.
        val m = vec("messages.json")
        val a = identity("A")
        val b = identity("B")
        for (c in arr(m["connections"]).map { obj(it) }) {
            val key = checkConnection(c)
            val request = messagePlain(c, "request", key)
            val response = messagePlain(c, "response", key)
            val hello = obj(c["hello"])
            val client = LanClient(
                a, groupKey(), HelloCounterSource(MemoryCounterStore(), FixedClock(0)),
                QueueRandom(listOf(Vectors.hex(str(c["session_id"])), Vectors.hex(str(obj(hello["initiator"])["nonce_hex"])))),
                FixedClock(0),
            )
            var seen = ByteArray(0)
            val conn = FakeConnection(b, pinned("A"), 1, Vectors.hex(str(obj(hello["responder"])["nonce_hex"]))) {
                seen = it
                response
            }
            val got = client.request(request, pinned("B"), conn)
            assertContentEquals(response, got)
            assertContentEquals(request, seen)
            val recorded = SessionHello.parse(bytes(str(obj(hello["initiator"])["text"])))
            assertEquals(recorded.unsignedJson, conn.clientHello?.unsignedJson)
            assertEquals(recorded, conn.clientHello)
            // B's recorded hello recreated (same session id, nonce and counter).
            val recordedB = SessionHello.parse(bytes(str(obj(hello["responder"])["text"])))
            assertEquals(recordedB, conn.localHello)
            assertContentEquals(bytes(str(obj(hello["responder"])["text"])), conn.localHello!!.toBytes())
        }
    }

    private class RecordedViews(val aStates: List<ItemState>, val bResponses: List<ByteArray>, val bStates: List<ItemState>)

    private fun recordedViews(): RecordedViews {
        val m = vec("messages.json")
        val gk = groupKey()
        val viewA = java.io.ByteArrayOutputStream()
        val viewB = java.io.ByteArrayOutputStream()
        val responses = ArrayList<ByteArray>()
        for (c in arr(m["connections"]).map { obj(it) }) {
            val key = checkConnection(c)
            val req = LanMessages.parse(messagePlain(c, "request", key))
            if (req is LanMessage.View) viewA.write(Base64Std.decodeStrict(req.view))
            val resp = messagePlain(c, "response", key)
            responses.add(resp)
            val r = LanMessages.parse(resp)
            if (r is LanMessage.View) viewB.write(Base64Std.decodeStrict(r.view))
        }
        return RecordedViews(
            ViewFile.decode(viewA.toByteArray(), gk, identity("A").deviceId).second,
            responses,
            ViewFile.decode(viewB.toByteArray(), gk, identity("B").deviceId).second,
        )
    }

    @Test
    fun client_sync_choreography_with_live_responder() {
        val rv = recordedViews()
        val a = identity("A")
        val b = identity("B")
        val gk = groupKey()
        val received = java.io.ByteArrayOutputStream()
        val kinds = ArrayList<String>()
        val connector = FakeConnector { n ->
            FakeConnection(b, pinned("A"), (n + 1).toLong(), null) { req ->
                val msg = LanMessages.parse(req)
                when {
                    n == 0 && msg is LanMessage.View && msg.seq == 0L && msg.total == 2L -> {
                        kinds.add("view0")
                        received.write(Base64Std.decodeStrict(msg.view))
                        LanMessages.encode(LanMessage.Ack(msg.transfer, 0))
                    }
                    n == 1 && msg is LanMessage.View && msg.seq == 1L && msg.total == 2L -> {
                        kinds.add("view1")
                        received.write(Base64Std.decodeStrict(msg.view))
                        rv.bResponses[1]
                    }
                    n == 2 && msg is LanMessage.Next && msg.seq == 1L -> {
                        kinds.add("next1")
                        val tb = LanMessages.parse(rv.bResponses[1]) as? LanMessage.View ?: throw LanSyncException("bad-test")
                        if (tb.transfer != msg.transfer) throw LanSyncException("bad-test")
                        rv.bResponses[2]
                    }
                    else -> throw LanSyncException("unexpected", "$n $msg")
                }
            }
        }
        val store = MemoryCounterStore()
        val client = LanClient(a, gk, HelloCounterSource(store, FixedClock(1790000900)), SystemRandomSource(), FixedClock(1790000900))
        val states = client.sync(pinned("B"), rv.aStates, 7, connector)
        assertEquals(listOf("view0", "view1", "next1"), kinds)
        assertEquals(rv.bStates, states)
        val sent = ViewFile.decode(received.toByteArray(), gk, a.deviceId)
        assertEquals(rv.aStates, sent.second)
        assertEquals(7L, sent.first.counter)
        // Three connections, three distinct increasing hello counters; the responder's were recorded.
        val counters = connector.opened.mapNotNull { it.clientHello?.counter }
        assertEquals(listOf(1790000900_000_000L, 1790000900_000_001L, 1790000900_000_002L), counters)
        assertEquals(3L, store.inbound[b.deviceId])
    }

    /** Fails like a dropped hello: records the client's hello, then throws [LanPeerNotAnswering]. */
    private class DroppingConnection : LanConnection {
        var hello: SessionHello? = null

        override fun exchange(frame: ByteArray): ByteArray {
            hello = SessionHello.parse(LanTransport.decodeFrame(frame))
            throw LanPeerNotAnswering("reply lost")
        }
    }

    private class ScriptConnector(val make: (Int) -> LanConnection) : LanConnector {
        val opened = ArrayList<LanConnection>()

        override fun connect(peer: PinnedPeer): LanConnection {
            val c = make(opened.size)
            opened.add(c)
            return c
        }
    }

    @Test
    fun unanswered_request_is_retried_once_with_a_new_hello() {
        val rv = recordedViews()
        val a = identity("A")
        val b = identity("B")
        val gk = groupKey()
        val dropped = DroppingConnection()
        val live = ArrayList<FakeConnection>()
        var n = 0
        val connector = ScriptConnector { i ->
            if (i == 1) {
                dropped // the second request's hello gets no answer
            } else {
                n += 1
                val c = FakeConnection(b, pinned("A"), n.toLong(), null) { req ->
                    val msg = LanMessages.parse(req)
                    when {
                        msg is LanMessage.View && msg.seq == 0L -> LanMessages.encode(LanMessage.Ack(msg.transfer, 0))
                        msg is LanMessage.View && msg.seq == 1L -> rv.bResponses[1]
                        msg is LanMessage.Next -> rv.bResponses[2]
                        else -> throw LanSyncException("unexpected")
                    }
                }
                live.add(c)
                c
            }
        }
        val sleeps = ArrayList<Long>()
        val client = LanClient(
            a, gk, HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900)), SystemRandomSource(), FixedClock(1790000900),
            sleep = { sleeps.add(it) },
        )
        val states = client.sync(pinned("B"), rv.aStates, 7, connector)
        assertEquals(rv.bStates, states)
        assertEquals(4, connector.opened.size)
        assertEquals(listOf(50L), sleeps)
        val lost = dropped.hello!!
        val retried = live[1].clientHello!!
        assertTrue(retried.counter > lost.counter)
        assertTrue(!retried.sessionId.contentEquals(lost.sessionId))
        assertTrue(!retried.toBytes().contentEquals(lost.toBytes()))
    }

    @Test
    fun first_request_and_second_failure_are_not_retried() {
        val rv = recordedViews()
        val a = identity("A")
        val gk = groupKey()
        val sleeps = ArrayList<Long>()
        val client = LanClient(
            a, gk, HelloCounterSource(MemoryCounterStore(), FixedClock(1790000900)), SystemRandomSource(), FixedClock(1790000900),
            sleep = { sleeps.add(it) },
        )
        // The first request is never retried.
        val first = ScriptConnector { DroppingConnection() }
        assertFailsWith<LanPeerNotAnswering> { client.sync(pinned("B"), rv.aStates, 7, first) }
        assertEquals(1, first.opened.size)
        assertEquals(emptyList(), sleeps)
        // A later request is retried once; when the retry fails too, that failure surfaces.
        var live = 0
        val second = ScriptConnector { i ->
            if (i == 0) {
                live++
                FakeConnection(identity("B"), pinned("A"), 1, null) { req ->
                    val msg = LanMessages.parse(req) as LanMessage.View
                    LanMessages.encode(LanMessage.Ack(msg.transfer, 0))
                }
            } else {
                DroppingConnection()
            }
        }
        assertFailsWith<LanPeerNotAnswering> { client.sync(pinned("B"), rv.aStates, 7, second) }
        assertEquals(1, live)
        assertEquals(3, second.opened.size) // chunk 0, chunk 1, its single retry
        assertEquals(listOf(50L), sleeps)
    }

    /**
     * Holds each caller of [persistedHelloCounter] (after it has read the value) until a second caller is
     * inside too, or 200 ms pass, so two unsynchronised sources both read the same persisted block end.
     */
    private class RacingStore(private val base: MemoryCounterStore = MemoryCounterStore()) : CounterStore by base {
        private val barrier = java.util.concurrent.CyclicBarrier(2)

        override fun persistedHelloCounter(): Long {
            val seen = base.persistedHelloCounter()
            try {
                barrier.await(200, java.util.concurrent.TimeUnit.MILLISECONDS)
            } catch (e: java.util.concurrent.TimeoutException) {
                // A serialized caller is released after the timeout.
            } catch (e: java.util.concurrent.BrokenBarrierException) {
                // Barrier already used or broken: carry on.
            }
            return seen
        }
    }

    private fun racedCounters(sourceFor: (Int) -> HelloCounterSource): List<Long> {
        val out = java.util.Collections.synchronizedList(ArrayList<Long>())
        val threads = (0 until 2).map { n ->
            val source = sourceFor(n)
            Thread { repeat(3) { out.add(source.nextCounter()) } }.also { it.start() }
        }
        threads.forEach { it.join(10_000) }
        assertTrue(threads.none { it.isAlive })
        return out
    }

    @Test
    fun one_shared_source_never_repeats_a_hello_counter_across_threads() {
        val store = RacingStore()
        val shared = HelloCounterSource(store, FixedClock(10))
        val got = racedCounters { shared }
        assertEquals(6, got.size)
        assertEquals(6, got.toSet().size, "repeated hello counter: $got")
    }

    @Test
    fun control_two_sources_over_one_store_do_repeat_a_hello_counter() {
        // Proves the race test can detect the bug: separate sources (separate locks) read the same persisted block.
        val store = RacingStore()
        val got = racedCounters { HelloCounterSource(store, FixedClock(10)) }
        assertEquals(6, got.size)
        assertTrue(got.toSet().size < 6, "expected a duplicate, got $got")
    }

    @Test
    fun client_rejects_non_increasing_responder_counter() {
        val a = identity("A")
        val b = identity("B")
        val store = MemoryCounterStore()
        val client = LanClient(a, groupKey(), HelloCounterSource(store, FixedClock(0)), SystemRandomSource(), FixedClock(0))
        val ack = LanMessages.encode(LanMessage.Error("bad-chunk"))
        client.request(bytes("x"), pinned("B"), FakeConnection(b, pinned("A"), 4, null) { ack })
        for (replay in listOf(4L, 3L)) {
            try {
                client.request(bytes("x"), pinned("B"), FakeConnection(b, pinned("A"), replay, null) { ack })
                fail("accepted counter $replay")
            } catch (e: LanTransportException) {
                assertEquals(LanTransportException.Kind.REPLAY, e.kind)
                assertEquals("Session hello counter did not increase", e.detail)
            }
        }
        // A refusal surfaces as the desktop issue code.
        val refusing = FakeConnector {
            FakeConnection(b, pinned("A"), 100, null) { LanMessages.encode(LanMessage.Error("rejoin-required")) }
        }
        assertEquals("peer-rejoin-required", syncReason { client.sync(pinned("B"), emptyList(), 0, refusing) })
        assertNotEquals(0, refusing.opened.size)
    }
}
