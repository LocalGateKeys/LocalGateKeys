package app.localgatekeys.core.sync

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.Ed25519
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.Vectors
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Every case of `tests/vectors/sync/removal/` (notices.json, writer.json, watch.json; see SCHEMA.md there). */
class RemovalVectorsTest {
    private fun doc(name: String) = Vectors.json(Vectors.sync("removal/$name")).obj().fields

    private val notices = doc("notices.json")

    private fun b64(v: JsonValue?): ByteArray = Base64Std.decodeStrict(str(v)!!)

    private fun long(v: JsonValue?): Long = (v as JsonValue.Int).v

    private fun watchOf(v: JsonValue?): RemovalWatch {
        val f = obj(v)
        return RemovalWatch(
            str(f["group_id"])!!, str(f["device_id"])!!, long(f["epoch"]), str(f["install_id"])!!, str(f["folder"])!!,
            obj(f["signers"]).mapValues { str(it.value)!! },
        )
    }

    private fun keyring(name: String): ByteArray = b64(obj(obj(notices["keyrings"])[name])["b64"])

    @Test fun constants_match() {
        val c = obj(notices["constants"])
        assertEquals(str(c["notice_label"]), Removal.NOTICE_LABEL.toString(Charsets.UTF_8))
        assertEquals(long(c["max_notice_bytes"]), Removal.MAX_NOTICE_BYTES.toLong())
        assertEquals(str(c["removed_dir"]), Removal.REMOVED_DIR_NAME)
        assertEquals(str(c["notice_suffix"]), Removal.NOTICE_SUFFIX)
        assertEquals(long(c["notice_format"]), Removal.NOTICE_FORMAT)
    }

    @Test fun every_notice_case_verifies_as_python() {
        val cases = arr(notices["cases"])
        assertEquals(80, cases.size)
        val watches = obj(notices["watches"])
        val wrong = ArrayList<String>()
        for (c in cases.map { obj(it) }) {
            val name = str(c["name"])!!
            val exp = obj(c["expected"])
            val accept = (exp["accept"] as JsonValue.Bool).v
            val got: Any = try {
                Removal.verifyNotice(b64(c["notice_b64"]), watchOf(watches[str(c["watch"])]), keyring(str(c["folder_keyring"])!!))
            } catch (e: RemovalException) {
                e.reason
            }
            if (accept) {
                val n = obj(exp["notice"])
                val want = RemovalNotice(str(n["group_id"])!!, str(n["device_id"])!!, long(n["epoch"]), str(n["signer"])!!, long(n["issued_at"]))
                if (got != want) wrong.add("$name: $got")
            } else if (got != str(exp["reason"])) {
                wrong.add("$name: got $got, want ${str(exp["reason"])}")
            }
        }
        assertTrue(wrong.isEmpty(), wrong.joinToString("\n"))
    }

    @Test fun writer_is_byte_identical() {
        val w = doc("writer.json")
        for (c in arr(w["cases"]).map { obj(it) }) {
            val i = obj(c["inputs"])
            val seed = b64(i["signing_private_seed_b64"])
            val raw = Removal.makeNotice(str(i["group_id"])!!, str(i["device_id"])!!, long(i["epoch"]), str(i["signer"])!!, long(i["issued_at"])) {
                Ed25519.sign(seed, it)
            }
            assertEquals(str(c["notice_text"]), raw.toString(Charsets.UTF_8))
            assertEquals(str(c["notice_sha256"]), Vectors.hexString(MessageDigest.getInstance("SHA-256").digest(raw)))
            assertEquals(str(c["path"]), Removal.noticePath(str(i["device_id"])!!))
            val (_, message, sig) = Removal.parseNotice(raw)
            assertEquals(str(c["signed_message_hex"]), Vectors.hexString(message))
            assertEquals(str(c["sig_b64"]), Base64Std.encode(sig))
        }
        for (r in arr(w["refusals"]).map { obj(it) }) {
            val i = obj(r["inputs"])
            val e = assertFailsWith<RemovalException> {
                Removal.makeNotice(str(i["group_id"])!!, str(i["device_id"])!!, long(i["epoch"]), str(i["signer"])!!, long(i["issued_at"])) { ByteArray(64) }
            }
            assertEquals(str(r["error"]), e.reason, str(r["description"]))
        }
    }

    private val watch = doc("watch.json")

    @Test fun watch_paths_and_example() {
        val c = obj(watch["constants"])
        assertEquals(str(c["watch_suffix"]), Removal.WATCH_SUFFIX)
        assertEquals(long(c["max_watch_bytes"]), Removal.MAX_WATCH_BYTES.toLong())
        assertEquals(long(c["watch_version"]), Removal.WATCH_VERSION)
        for (p in arr(watch["paths"]).map { obj(it) }) assertEquals(str(p["watch"]), Removal.watchFileName(str(p["vault"])!!))
        val ex = obj(watch["example"])
        val parsed = watchOf(ex["parsed"])
        assertEquals(str(ex["watch_text"]), parsed.encode().toString(Charsets.UTF_8))
        assertEquals(parsed, Removal.parseWatch(str(ex["watch_text"])!!.toByteArray(Charsets.UTF_8)))
    }

    @Test fun watch_derive() {
        for (d in arr(watch["derive"]).map { obj(it) }) {
            val s = obj(d["state"])
            val base = SyncGroupState(
                groupId = str(s["group_id"])!!, epoch = long(s["epoch"]), key = ByteArray(32),
                identity = identityWithId(str(s["device_id"])!!), installId = str(s["install_id"])!!,
                keyring = keyring(str(s["keyring"])!!),
            )
            val unacked = arr(s["unacked_members"]).map { str(it)!! }
            val w = Removal.watchFromState(base, str(d["folder"])!!, unacked)!!
            assertEquals(str(d["watch_text"]), w.encode().toString(Charsets.UTF_8), str(d["name"]))
            // The state's own list is the default.
            assertEquals(w, Removal.watchFromState(base.copy(unackedMembers = unacked), str(d["folder"])!!))
        }
    }

    @Test fun watch_parse() {
        for (p in arr(watch["parse"]).map { obj(it) }) {
            val got = Removal.parseWatch(b64(p["b64"]))
            val exp = p["expected"]
            if (exp == null || exp == JsonValue.Null) assertNull(got, str(p["name"])) else assertEquals(watchOf(exp), got, str(p["name"]))
        }
    }

    @Test fun watch_pinned() {
        for (p in arr(watch["pinned"]).map { obj(it) }) {
            val old = p["old"].let { if (it == null || it == JsonValue.Null) null else watchOf(it) }
            assertEquals(watchOf(p["expected"]), Removal.pinned(watchOf(p["fresh"]), old), str(p["name"]))
        }
    }

    /** Only the device id matters to [Removal.watchFromState]; the keys are a known identity's. */
    private fun identityWithId(id: String) = app.localgatekeys.core.lan.DeviceIdentity(id, ByteArray(32) { 1 }, ByteArray(32) { 2 })
}
