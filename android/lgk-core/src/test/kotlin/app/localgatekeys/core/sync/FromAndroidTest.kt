package app.localgatekeys.core.sync

import app.localgatekeys.core.backup.PhoneBackupFormat
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.passkey.PasskeyKey
import app.localgatekeys.core.passkey.PasskeyRecord
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.Normalise
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.NOTE
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.INSTALL
import app.localgatekeys.core.support.SyncFixtures.KEYRING_PATH
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.SyncFixtures.epochKey
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * The Android equivalent of Swift `FolderSyncTests.test_writes_from_ios_vectors` (flow `fromIOSFlow`).
 *
 * `LGK_WRITE_FROM_ANDROID=1` rewrites tests/vectors/sync/from_android/{keyring.lgkkeys,devices/<id>.lgksync}
 * and tests/vectors/backup/from_android/backup.lgkm; otherwise the in-memory bytes must equal the committed files.
 * The desktop reads them in tests/test_sync_from_android.py and tests/test_backup_from_android.py.
 */
class FromAndroidTest {
    class Out(
        val keyring: ByteArray,
        val deviceId: String,
        val file: ByteArray,
        val store: MemoryStore,
        val backup: ByteArray,
    )

    private companion object {
        const val DEVICE_NAME = "Pixel (Android)"
        const val PHONE_LOGIN = "f1050000-0000-4000-8000-000000000201"
        const val PHONE_PASSKEY = "f1050000-0000-4000-8000-000000000202"
        const val BACKUP_PASSWORD = "correct horse battery staple 42"

        /** The desktop-made key from passkeys/records.json, so the phone-made passkey is reproducible. */
        const val PASSKEY_KEY =
            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQggJAFr4R6ySgU2NEGD-pDv92Ax8nnc5g7dPnxMB-ag4uhRANCAARvaw4fOvc3kChJM_Bpa34YDtimWWrF2-Of20DTY7TibutHLx7hAnjZggvTyYrgq668kur1CSNCs1C59qhpNXaB"
    }

    /**
     * join with the real password, merge A/B/C, create a web login, edit the note, create a passkey, run again;
     * then write the phone backup of the resulting local view. Randomness: ONE DetRand("from-android") stream
     * used by the join, the second run and, last, the backup (its salt, then its nonce).
     */
    private fun fromAndroidFlow(): Out {
        val folder = SyncFixtures.seededFolder()
        val store = MemoryStore()
        val fs = FolderSync(folder, INSTALL)
        val rand = DetRand("from-android")
        val password = str(SyncFixtures.expected()["password_epoch1"])!!
        val first = fs.join(store, password, DEVICE_NAME, rand, FixedClock(T0 + 1000))
        check(first.issues.isEmpty() && first.wrote) { "first run: ${first.issues}" }
        val snap0 = store.snapshot
        val login = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(PHONE_LOGIN),
                "kind" to JsonValue.Str("web"),
                "label" to JsonValue.Str("Créé sur Android"),
                "username" to JsonValue.Str("android.user"),
                "password" to JsonValue.Str("from-android-sample-pass"),
                "scope" to JsonValue.Obj(mapOf("origin" to JsonValue.Str("https://Example.org:443"))),
                "created_at" to JsonValue.Int(T0 + 1010),
                "updated_at" to JsonValue.Int(T0 + 1010),
                "favorite" to JsonValue.Bool(true),
                "tags" to JsonValue.Arr(listOf(JsonValue.Str("android"))),
                "notes" to JsonValue.Str("written by the Kotlin core"),
            ),
        )
        val records = LinkedHashMap(snap0.records)
        records[PHONE_LOGIN] = Wrapper.make(Namespace.ENTRY, Normalise.normalForm(Namespace.ENTRY, login))
        val note = LinkedHashMap(obj(obj(records[NOTE])["record"]))
        note["title"] = JsonValue.Str("Edited on Android")
        note["updated_at"] = JsonValue.Int(T0 + 1020)
        records[NOTE] = Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, JsonValue.Obj(note)))
        val made = PasskeyRecord.newPayload(
            rpId = "passkeys.example",
            rpName = "Passkeys Example",
            userName = "android.user",
            userDisplayName = "Android User",
            userHandle = "android-user-handle".toByteArray(Charsets.UTF_8),
            credentialId = ByteArray(16) { (0x20 + it).toByte() },
            key = PasskeyKey.fromPkcs8B64Url(PASSKEY_KEY)!!,
            today = "2026-10-23",
        )
        val passkey = JsonValue.Obj(
            mapOf(
                "id" to JsonValue.Str(PHONE_PASSKEY),
                "kind" to JsonValue.Str("passkey"),
                "title" to JsonValue.Str(made.title),
                "created_at" to JsonValue.Int(T0 + 1025),
                "updated_at" to JsonValue.Int(T0 + 1025),
                "favorite" to JsonValue.Bool(false),
                "tags" to JsonValue.Arr(emptyList()),
                "payload" to made.fields,
            ),
        )
        records[PHONE_PASSKEY] = Wrapper.make(Namespace.ITEM, Normalise.normalForm(Namespace.ITEM, passkey))
        store.snapshot = snap0.copy(records = records)
        val second = fs.runOnce(store, rand, FixedClock(T0 + 1030))
        check(second.issues.isEmpty() && second.wrote) { "second run: ${second.issues}" }
        val snap = store.snapshot
        val id = snap.sync!!.deviceId
        // The phone backup: the states this device's own local view publishes (stored form).
        val view = SyncMeta.localView(snap.records, snap.meta, id, T0 + 1030)
        val states = view.states.values.sortedBy { it.itemId }
        val backup = PhoneBackupFormat.write(states, BACKUP_PASSWORD, id, "android", "1.0.0", T0 + 1030, false, rand)
        return Out(folder.files[KEYRING_PATH]!!, id, folder.files[devPath(id)]!!, store, backup)
    }

    /** [ring] as format 1: members without `signing_public` / `signing_proof`, MAC recomputed under [gk]. */
    private fun asFormat1(ring: JsonValue, gk: app.localgatekeys.core.group.GroupKey): ByteArray {
        val body = LinkedHashMap(obj(ring))
        body["format"] = JsonValue.Int(1)
        body["members"] = JsonValue.Arr(
            (body["members"] as JsonValue.Arr).items.map { JsonValue.Obj(obj(it) - "signing_public" - "signing_proof") },
        )
        return CanonicalJson.encode(Keyring.finish(body, gk), Dialect.UTF8)
    }

    private fun read(f: File): ByteArray {
        check(f.isFile) { "vector missing: $f (generate with LGK_WRITE_FROM_ANDROID=1)" }
        return f.readBytes()
    }

    @Test
    fun writes_from_android_vectors() {
        val out = fromAndroidFlow()
        // Reproducible: the same flow gives the same bytes.
        val again = fromAndroidFlow()
        assertContentEquals(again.keyring, out.keyring)
        assertContentEquals(again.file, out.file)
        assertContentEquals(again.backup, out.backup)
        assertEquals(again.deviceId, out.deviceId)
        // Derived from the DetRand("from-android") stream by the join, as Swift pins bcc03464-... for iOS.
        assertEquals("7086dd0d-47e4-4d5c-864a-d61f6196ab85", out.deviceId)

        // The desktop's checks: the keyring is accepted with the epoch-1 key (as identity B), the file decodes.
        val gk = epochKey("1")
        val ring = Keyring.parse(out.keyring)
        assertEquals(gk, Keyring.accept(ring, gk, SyncFixtures.identity("B")))
        val (header, states) = ViewFile.decode(out.file, gk, out.deviceId)
        assertEquals(2L, header.counter)
        val received = SyncFixtures.bridgeStoredStates().associateBy { it.itemId }
        var phoneEdited = 0
        for (s in states) {
            val item = s.item
            if (item == null) {
                assertEquals(received[s.itemId], s, s.itemId) // tombstones republished unchanged
                continue
            }
            val w = obj(item)
            val ns = Namespace.entries.first { it.wire == str(w["ns"]) }
            val kind = str(obj(w["record"])["kind"]) ?: ""
            if (kind in Normalise.phoneEntryKinds || kind in Normalise.phoneItemKinds) {
                assertEquals(Normalise.normalForm(ns, w["record"]!!), w["record"]!!, s.itemId)
            }
            if (s.itemId == PHONE_LOGIN || s.itemId == PHONE_PASSKEY || s.itemId == NOTE) {
                phoneEdited++
                assertEquals(1L, s.vv[out.deviceId], s.itemId)
            } else {
                assertEquals(received[s.itemId], s, "${s.itemId} must be republished unchanged")
                assertContentEquals(
                    CanonicalJson.encode(item, Dialect.UTF8),
                    CanonicalJson.encode(received[s.itemId]!!.item!!, Dialect.UTF8),
                )
            }
        }
        assertEquals(3, phoneEdited)
        assertEquals(received.keys + setOf(PHONE_LOGIN, PHONE_PASSKEY), states.map { it.itemId }.toSet())

        // The backup opens with the password and holds exactly the device file's states.
        val backup = PhoneBackupFormat.read(out.backup, BACKUP_PASSWORD)
        assertEquals("android", backup.header.platform)
        assertEquals(T0 + 1030, backup.header.createdAt)
        assertEquals(out.deviceId, backup.deviceId)
        assertEquals("1.0.0", backup.appVersion)
        assertEquals(false, backup.proHint)
        assertEquals(states.sortedBy { it.itemId }, backup.states)
        assertNotNull(out.store.snapshot.sync)

        val sync = File(Vectors.root, "sync/from_android")
        val bak = File(Vectors.root, "backup/from_android")
        if (System.getenv("LGK_WRITE_FROM_ANDROID") == "1") {
            File(sync, "devices").mkdirs()
            bak.mkdirs()
            File(sync, "keyring.lgkkeys").writeBytes(out.keyring)
            File(sync, "devices/${out.deviceId}.lgksync").writeBytes(out.file)
            File(bak, "backup.lgkm").writeBytes(out.backup)
        }
        // The join writes keyring format 2 (the phone's entry lists its signing key with a proof; the
        // members from the format-1 seed get null signing fields).
        assertEquals(JsonValue.Int(2), obj(ring)["format"])
        assertEquals(
            mapOf(out.deviceId to Base64Std.encode(out.store.snapshot.sync!!.identity.signingPublicKey)),
            Keyring.memberSigningKeys(ring),
        )
        // A committed format-1 file (written before format 2) must equal the output with the signing fields
        // dropped and the MAC recomputed; a regenerated (format 2) file must equal the output exactly.
        val committed = read(File(sync, "keyring.lgkkeys"))
        if (obj(Keyring.parse(committed))["format"] == JsonValue.Int(1)) {
            assertContentEquals(committed, asFormat1(ring, gk))
        } else {
            assertContentEquals(out.keyring, committed)
        }
        assertContentEquals(out.file, read(File(sync, "devices/${out.deviceId}.lgksync")))
        assertContentEquals(out.backup, read(File(bak, "backup.lgkm")))
        assertEquals(listOf("${out.deviceId}.lgksync"), File(sync, "devices").list()!!.toList())
    }
}
