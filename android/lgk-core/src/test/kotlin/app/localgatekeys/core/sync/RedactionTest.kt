package app.localgatekeys.core.sync

import app.localgatekeys.core.backup.BackupHeader
import app.localgatekeys.core.backup.PhoneBackup
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.passkey.Passkey
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotSame
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** No plaintext record or key byte reaches a toString; byte arrays never leak out of value types. */
class RedactionTest {
    private companion object {
        const val SECRET = "hunter2-S3cret-Passw0rd"
        const val TOTP = "JBSWY3DPEHPK3PXP"
    }

    private fun item(): JsonValue = JsonValue.Obj(
        mapOf(
            "ns" to JsonValue.Str("entry"),
            "schema" to JsonValue.Int(1),
            "updated_at" to JsonValue.Int(5),
            "record" to JsonValue.Obj(
                mapOf(
                    "id" to JsonValue.Str("a1"),
                    "password" to JsonValue.Str(SECRET),
                    "totp" to JsonValue.Str(TOTP),
                ),
            ),
        ),
    )

    private fun state(): ItemState = ItemState("a1", mapOf("phone" to 2L), false, null, item())

    private fun group(key: ByteArray = ByteArray(32) { 7 }, keyring: ByteArray? = byteArrayOf(1, 2, 3)) = SyncGroupState(
        groupId = "g1", epoch = 1, key = key, identity = DeviceIdentity.generate(random = DetRand("redaction")),
        installId = "install", keyring = keyring,
    )

    private fun assertRedacted(text: String, what: String) {
        assertFalse(text.contains(SECRET), "$what leaks the password: $text")
        assertFalse(text.contains(TOTP), "$what leaks the TOTP secret: $text")
        assertFalse(text.contains("password"), "$what leaks record field names: $text")
    }

    @Test
    fun item_state_to_string_shows_sync_fields_but_not_the_item() {
        val s = state().toString()
        assertRedacted(s, "ItemState")
        assertEquals("ItemState(itemId=a1, vv={phone=2}, deleted=false, deletedAt=null, item=<redacted>)", s)
        assertEquals(
            "ItemState(itemId=b2, vv={phone=1}, deleted=true, deletedAt=7, item=null)",
            ItemState("b2", mapOf("phone" to 1L), true, 7, null).toString(),
        )
    }

    @Test
    fun store_snapshot_store_change_and_run_report_are_count_only() {
        val records = mapOf("a1" to item())
        val meta = mapOf("a1" to SyncMeta("d".repeat(64), "b".repeat(64), 5, mapOf("phone" to 2L), false, null))
        val g = group()
        val snap = StoreSnapshot(records, meta, g, 3)
        assertRedacted(snap.toString(), "StoreSnapshot")
        assertEquals("StoreSnapshot(records=1, meta=1, sync=set, revision=3)", snap.toString())
        val change = StoreChange(3, records, meta, null)
        assertRedacted(change.toString(), "StoreChange")
        assertEquals("StoreChange(baseRevision=3, records=1, meta=1, sync=none)", change.toString())
        val report = RunReport(
            applied = 1, skipped = listOf("a1" to SECRET), issues = listOf(SyncIssue("corrupt", SECRET)),
            ownStates = listOf(state()), licenses = listOf(item()), records = records, meta = meta,
        )
        assertRedacted(report.toString(), "RunReport")
        assertEquals(
            "RunReport(applied=1, deleted=0, conflicts=0, skipped=1, issues=1, ownStates=1, wrote=false, licenses=1, " +
                "records=1, meta=1)",
            report.toString(),
        )
        // Key bytes never show either.
        assertFalse(g.toString().contains(g.key.contentToString()))
    }

    @Test
    fun phone_backup_to_string_is_count_only_and_shows_no_salt_or_nonce() {
        val salt = ByteArray(16) { 0x5A }
        val nonce = ByteArray(12) { 0x4E }
        val header = BackupHeader(1790000000, "android", mapOf("name" to "argon2id"), salt, nonce)
        val backup = PhoneBackup(header, "phone", "1.0.0", false, listOf(state()))
        val s = backup.toString()
        assertRedacted(s, "PhoneBackup")
        assertFalse(s.contains(salt.contentToString()) || s.contains(nonce.contentToString()), s)
        assertTrue(s.contains("states=1"), s)
    }

    @Test
    fun backup_header_salt_and_nonce_are_copied_in_and_out() {
        val salt = ByteArray(16) { 1 }
        val nonce = ByteArray(12) { 2 }
        val header = BackupHeader(1, "ios", emptyMap(), salt, nonce)
        salt[0] = 99
        nonce[0] = 99
        assertContentEquals(ByteArray(16) { 1 }, header.salt)
        assertContentEquals(ByteArray(12) { 2 }, header.nonce)
        header.salt[1] = 99
        header.nonce[1] = 99
        assertContentEquals(ByteArray(16) { 1 }, header.salt)
        assertContentEquals(ByteArray(12) { 2 }, header.nonce)
        assertNotSame(header.salt, header.salt)
        val same = BackupHeader(1, "ios", emptyMap(), ByteArray(16) { 1 }, ByteArray(12) { 2 })
        assertEquals(same, header)
        assertEquals(same.hashCode(), header.hashCode())
        assertEquals(header, header.copy())
        assertNotEquals(header, header.copy(salt = ByteArray(16)))
    }

    @Test
    fun sync_group_state_copies_key_and_keyring_in_and_out() {
        val key = ByteArray(32) { 7 }
        val ring = byteArrayOf(1, 2, 3)
        val g = group(key, ring)
        // Mutating the arrays passed in does not change the state.
        key[0] = 0
        ring[0] = 0
        assertContentEquals(ByteArray(32) { 7 }, g.key)
        assertContentEquals(byteArrayOf(1, 2, 3), g.keyring)
        // Mutating returned arrays does not either.
        g.key[1] = 0
        g.keyring!![1] = 0
        assertContentEquals(ByteArray(32) { 7 }, g.key)
        assertContentEquals(byteArrayOf(1, 2, 3), g.keyring)
        assertNotSame(g.key, g.key)
        assertEquals(GroupKey("g1", 1, ByteArray(32) { 7 }), g.groupKey())
        // copy keeps working, and equality/hashCode are by content.
        val same = group(ByteArray(32) { 7 }, byteArrayOf(1, 2, 3))
        assertEquals(same, g)
        assertEquals(same.hashCode(), g.hashCode())
        val c = g.copy(ownCounter = 5)
        assertEquals(5, c.ownCounter)
        assertContentEquals(g.key, c.key)
        assertNotEquals(g, c)
        assertEquals(g, c.copy(ownCounter = 0))
        val newKey = ByteArray(32) { 9 }
        val rekeyed = g.copy(key = newKey, keyring = null)
        newKey[0] = 0
        assertContentEquals(ByteArray(32) { 9 }, rekeyed.key)
        assertNull(rekeyed.keyring)
        assertNotEquals(g, rekeyed)
        assertNotEquals(g, g.copy(keyring = byteArrayOf(1, 2, 4)))
    }

    @Test
    fun public_byte_constants_are_fresh_copies() {
        val constants: List<Pair<String, () -> ByteArray>> = listOf(
            "RECORD_INFO" to { GroupKey.RECORD_INFO },
            "FILE_INFO" to { GroupKey.FILE_INFO },
            "MAGIC" to { ViewFile.MAGIC },
            "REQUEST_MAGIC" to { Enrollment.REQUEST_MAGIC },
            "REPLY_MAGIC" to { Enrollment.REPLY_MAGIC },
            "REFUSED_MAGIC" to { Enrollment.REFUSED_MAGIC },
            "AAGUID" to { Passkey.AAGUID },
        )
        val gk = GroupKey("g1", 1, ByteArray(32) { 3 })
        val recordKey = gk.recordKey
        val fileKey = gk.fileKey
        for ((name, get) in constants) {
            val before = get()
            val got = get()
            got.fill(0)
            assertContentEquals(before, get(), name)
            assertNotSame(get(), get(), name)
        }
        // Derivations still use the untouched labels.
        assertContentEquals(recordKey, gk.recordKey)
        assertContentEquals(fileKey, gk.fileKey)
        assertEquals("4c474b53594e43310a", Vectors.hexString(ViewFile.MAGIC))
        assertEquals("b7d2a6f01c4e4a5b9e3d5a1f7c2e8d41", Vectors.hexString(Passkey.AAGUID))
    }
}
