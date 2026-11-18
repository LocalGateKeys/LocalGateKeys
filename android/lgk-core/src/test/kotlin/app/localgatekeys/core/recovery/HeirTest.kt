package app.localgatekeys.core.recovery

import app.localgatekeys.core.crypto.Bip39
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** `.lgkheir` packages and the plan record against tests/vectors/heir/v1.json, written by the desktop. */
class HeirTest {
    private val v = HeirVectors.data
    private fun s(k: String) = v.getValue(k).str()
    private fun hex(k: String) = Vectors.hex(s(k))
    private val packages = v.getValue("packages").arr().map { it.str().toByteArray(Charsets.UTF_8) }
    private val shares = v.getValue("shares").arr().map { Vectors.hex(it.str()) }

    @Test fun names_refuse_control_format_and_private_use_but_not_unassigned() {
        // U+2FFFE is unassigned on every Unicode version: it stands for an emoji newer than this device's tables.
        val newer = String(Character.toChars(0x2FFFE))
        assertEquals("Anna $newer", Heir.printable("  Anna $newer ", 64))
        for (bad in listOf("Anna", "Anna‎", "Anna")) {
            assertEquals("invalid", assertFailsWith<HeirException> { Heir.printable(bad, 64) }.reason, bad)
        }
    }

    @Test fun reads_every_package_python_wrote() {
        val facts = v.getValue("shards").arr().map { it.obj().fields }
        packages.forEachIndexed { i, data ->
            val shard = Heir.readPackage(data)
            assertEquals(facts[i].getValue("index").long().toInt(), shard.index)
            assertEquals(facts[i].getValue("holder").str(), shard.holder)
            assertEquals(facts[i].getValue("package_id").str(), shard.packageId)
            assertEquals(s("plan_id"), shard.planId)
            assertEquals(s("owner"), shard.owner)
            assertEquals(v.getValue("k").long().toInt(), shard.k)
            assertEquals(v.getValue("created").long(), shard.created)
            assertContentEquals(shares[i], shard.share)
            assertEquals(s("signer"), Base64Std.encode(shard.signer))
        }
    }

    @Test fun any_k_packages_combine_to_the_entropy_and_its_phrase() {
        for (pair in listOf(listOf(0, 1), listOf(1, 2), listOf(2, 0), listOf(0, 1, 2))) {
            val entropy = Heir.combinePackages(pair.map { packages[it] })
            assertContentEquals(hex("entropy"), entropy)
            assertEquals(s("phrase"), Bip39.phrase(entropy))
        }
        val e = assertFailsWith<HeirException> { Heir.combinePackages(packages.take(1)) }
        assertEquals("need-more", e.reason)
        assertEquals(1, e.missing)
        assertEquals("duplicate", assertFailsWith<HeirException> { Heir.combinePackages(listOf(packages[0], packages[0])) }.reason)
        assertEquals("need-more", assertFailsWith<HeirException> { Heir.combinePackages(emptyList()) }.reason)
    }

    @Test fun derives_check_backup_and_holder_keys_like_the_desktop() {
        val entropy = hex("entropy")
        val salt = hex("check_salt")
        assertContentEquals(hex("check"), Heir.entropyCheck(entropy, s("plan_id"), salt))
        assertContentEquals(hex("backup_public"), Heir.backupPublicKey(entropy, s("plan_id"), salt))
        v.getValue("holder_keys").arr().forEachIndexed { i, h ->
            assertContentEquals(Vectors.hex(h.str()), Heir.holderKey(shares[i], s("plan_id"), salt))
        }
        assertTrue(Heir.verifyEntropy(s("plan_id"), salt, hex("check"), entropy))
        assertFalse(Heir.verifyEntropy(s("plan_id"), salt, hex("check"), entropy.copyOf().also { it[0] = (it[0] + 1).toByte() }))
    }

    @Test fun reseals_every_package_byte_for_byte() {
        val holders = v.getValue("holders").arr().map { it.str() }
        val ids = v.getValue("package_ids").arr().map { it.str() }
        packages.forEachIndexed { i, data ->
            val again = Heir.sealPackage(
                s("plan_id"), shares[i], holders[i], v.getValue("k").long().toInt(), v.getValue("n").long().toInt(),
                v.getValue("wait_days").long().toInt(), v.getValue("created").long(), hex("check_salt"), hex("check"),
                s("owner"), ids[i], hex("signing_seed"),
            )
            assertContentEquals(data, again, "package $i")
        }
    }

    @Test fun split_with_the_vector_coefficients_gives_the_desktop_shares() {
        val coeffs = hex("coefficients")
        val out = Sss.split(hex("entropy"), 2, 3, app.localgatekeys.core.support.FixedRandom(coeffs))
        out.zip(shares).forEach { (a, b) -> assertContentEquals(b, a) }
    }

    @Test fun refuses_what_the_desktop_refuses() {
        val refused = v.getValue("refused").arr().map { it.obj().fields }
        assertEquals(20, refused.size)
        for (case in refused) {
            val name = case.getValue("name").str()
            val e = assertFailsWith<HeirException>(name) { Heir.readPackage(case.getValue("package").str().toByteArray(Charsets.UTF_8)) }
            assertEquals(case.getValue("reason").str(), e.reason, name)
        }
    }

    @Test fun mixed_plans_and_a_forged_share_are_refused() {
        // A share re-signed under another key looks like another plan.
        val other = Heir.sealPackage(
            s("plan_id"), shares[1], "Anna", 2, 3, 7, v.getValue("created").long(), hex("check_salt"), hex("check"),
            s("owner"), "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74", ByteArray(32) { 9 },
        )
        assertEquals("mixed-plans", assertFailsWith<HeirException> { Heir.combinePackages(listOf(packages[0], other)) }.reason)
        // A wrong share signed with the plan key fails the HKDF check.
        val wrong = shares[1].copyOf().also { it[5] = (it[5].toInt() xor 1).toByte() }
        val forged = Heir.sealPackage(
            s("plan_id"), wrong, "Anna", 2, 3, 7, v.getValue("created").long(), hex("check_salt"), hex("check"),
            s("owner"), "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74", hex("signing_seed"),
        )
        assertEquals("check-failed", assertFailsWith<HeirException> { Heir.combinePackages(listOf(packages[0], forged)) }.reason)
    }

    @Test fun qr_text_round_trips_and_matches_the_desktop() {
        val qr = v.getValue("qr").arr().map { it.str() }
        packages.forEachIndexed { i, data ->
            assertEquals(qr[i], Heir.shardQrText(data))
            assertContentEquals(data, Heir.packageFromQrText(qr[i]))
        }
        for (bad in listOf("lgkheir:", "lgkheir:a", "lgkhier:" + qr[0].removePrefix("lgkheir:"), qr[0] + "+", qr[0].dropLast(3))) {
            assertFailsWith<HeirException>(bad.take(12)) { Heir.packageFromQrText(bad) }
        }
    }

    @Test fun synced_record_and_merges_match_the_desktop() {
        val record = v.getValue("record")
        assertEquals(v.getValue("synced"), Heir.syncedRecord(record))
        val plan = Heir.parsePlan(v.getValue("synced"))
        assertEquals(listOf("Νίκος", "Anna", "Ben"), plan.holders)
        assertFalse(plan.stale)
        val cases = v.getValue("merges").arr().map { it.obj().fields }
        assertEquals(12, cases.size)
        for (case in cases) {
            val name = case.getValue("name").str()
            val local = case.getValue("local").takeIf { it != JsonValue.Null }
            val reason = case["reason"]?.str()
            if (reason != null) {
                val e = assertFailsWith<HeirException>(name) { Heir.mergeSynced(local, case.getValue("remote")) }
                assertEquals(reason, e.reason, name)
            } else {
                assertEquals(case.getValue("stored"), Heir.mergeSynced(local, case.getValue("remote")), name)
            }
        }
    }

    @Test fun with_denied_keeps_the_newest_and_moves_a_repeat_to_the_end() {
        val synced = v.getValue("synced") as JsonValue.Obj
        val id = "11111111-2222-4333-8444-555555555555"
        val once = Heir.withDenied(synced, id)
        val denied = (once.fields.getValue("denied") as JsonValue.Arr).items.map { it.str() }
        assertEquals(id, denied.last())
        val again = Heir.withDenied(Heir.withDenied(once, "7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59"), id)
        assertEquals(listOf("7f301c5e-9d4b-4ea2-8f63-4c8a0b2d1e59", id), (again.fields.getValue("denied") as JsonValue.Arr).items.map { it.str() })
        assertFailsWith<HeirException> { Heir.withDenied(synced, "not-an-id") }
    }

    @Test fun printable_names_follow_the_desktop() {
        assertEquals("Ann", Heir.printable("  Ann ", 32))
        assertEquals("é", Heir.printable("é", 32))
        assertFailsWith<HeirException> { Heir.printable("", 32) }
        assertEquals("", Heir.printable(" ", 64, allowEmpty = true))
        assertFailsWith<HeirException> { Heir.printable("a​b", 32) }
        assertFailsWith<HeirException> { Heir.printable("a\u0007", 32) }
        assertEquals("😀".repeat(32), Heir.printable("😀".repeat(32), 32)) // code points, not UTF-16 units
        assertFailsWith<HeirException> { Heir.printable("x".repeat(33), 32) }
    }
}

/** The shared heir vectors (read once). */
object HeirVectors {
    val data: Map<String, JsonValue> by lazy {
        Vectors.json(File(Vectors.root, "heir/v1.json").also { check(it.isFile) { "vector missing: $it" } }).obj().fields
    }
}
