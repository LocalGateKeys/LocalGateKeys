package app.localgatekeys.core.recovery

import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** The folder flow (port of tests/test_heir_flow.py, the parts a phone runs) and byte parity with the desktop's files. */
class HeirFlowTest {
    private val v = HeirVectors.data
    private fun s(k: String) = v.getValue(k).str()
    private fun hex(k: String) = Vectors.hex(s(k))
    private fun sub(k: String) = v.getValue(k).obj().fields
    private val packages = v.getValue("packages").arr().map { it.str().toByteArray(Charsets.UTF_8) }
    private val plan = Heir.parsePlan(v.getValue("synced"))
    private val planId = s("plan_id")
    private val created = v.getValue("created").long()
    private val random = SystemRandomSource()
    private val requester = sub("requester")
    private val identity = RequesterIdentity(Vectors.hex(requester.getValue("signing_seed").str()), Vectors.hex(requester.getValue("box_key").str()))
    private val dir = "LocalGateKeys Emergency/$planId"

    private fun planWith(edit: (MutableMap<String, JsonValue>) -> Unit): HeirPlan {
        val r = LinkedHashMap((v.getValue("synced") as JsonValue.Obj).fields)
        edit(r)
        return Heir.parsePlan(JsonValue.Obj(r))
    }

    private fun descriptor(folder: MemoryFolder) {
        val d = sub("descriptor")
        folder.files["$dir/${d.getValue("file").str()}"] = d.getValue("data").str().toByteArray(Charsets.UTF_8)
    }

    // ---- byte parity with the files Python wrote ----------------------------------------------

    @Test fun request_is_remade_byte_for_byte_and_verifies_on_the_owner() {
        val r = sub("request")
        val data = HeirFlow.requestBytes(packages[1], identity, r.getValue("id").str(), r.getValue("created").long())
        assertContentEquals(r.getValue("data").str().toByteArray(Charsets.UTF_8), data)
        val folder = MemoryFolder()
        folder.files["$dir/${r.getValue("file").str()}"] = data
        val pending = HeirFlow.pendingFor(planWith { it["denied"] = JsonValue.Arr(emptyList()) }, HeirFolder(folder), r.getValue("created").long(), random)
        assertEquals(1, pending.requests.size)
        assertEquals("Anna", pending.requests[0].holder)
        assertEquals(7, pending.requests[0].daysLeft)
        assertEquals(r.getValue("id").str(), pending.requests[0].requestId)
        assertEquals(RequesterIdentity.fromRecord(requester.getValue("record")).toRecord(), requester.getValue("record"))
    }

    @Test fun deny_and_grant_are_remade_byte_for_byte_and_the_grant_opens() {
        val r = sub("request")
        val d = sub("deny")
        assertContentEquals(
            d.getValue("data").str().toByteArray(Charsets.UTF_8),
            HeirFlow.denyBytes(plan, r.getValue("id").str(), d.getValue("created").long(), d.getValue("id").str()),
        )
        val folder = MemoryFolder()
        folder.files["$dir/${r.getValue("file").str()}"] = r.getValue("data").str().toByteArray(Charsets.UTF_8)
        val request = HeirFlow.pendingFor(planWith { it["denied"] = JsonValue.Arr(emptyList()) }, HeirFolder(folder), created, random).requests.single()
        val g = sub("grant")
        val grant = HeirFlow.grantBytes(plan, request, hex("entropy"), g.getValue("created").long(), Vectors.hex(g.getValue("ephemeral").str()), g.getValue("id").str())
        assertContentEquals(g.getValue("data").str().toByteArray(Charsets.UTF_8), grant)
        assertContentEquals(hex("entropy"), HeirFlow.openGrant(assertNotNull(HeirFlow.readGrant(grant)), identity))
        val stranger = RequesterIdentity(ByteArray(32) { 1 }, ByteArray(32) { 2 })
        assertNull(HeirFlow.openGrant(HeirFlow.readGrant(grant)!!, stranger))
    }

    @Test fun reads_the_desktop_backup_descriptor() {
        val folder = MemoryFolder()
        descriptor(folder)
        val list = HeirFlow.backups(HeirFolder(folder), dir, plan.signer, planId)
        assertEquals(1, list.size)
        assertEquals(sub("descriptor").getValue("written_at").long(), list[0].writtenAt)
        assertContentEquals(hex("backup_public"), list[0].backupPublic)
        assertTrue(HeirFlow.backups(HeirFolder(folder), dir, ByteArray(32), planId).isEmpty())
    }

    // ---- the flow -------------------------------------------------------------------------

    private val fresh = planWith { it["denied"] = JsonValue.Arr(emptyList()) }

    @Test fun request_wait_and_recover_after_the_waiting_period() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        val two = packages.take(2)
        assertEquals("none", HeirFlow.requestStatus(f, two, identity, created).state)
        assertEquals("no-request", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, two, identity, created) }.reason)
        val now = created + 100
        HeirFlow.requestAccess(f, packages[0], identity, now, random)
        val pending = HeirFlow.pendingFor(fresh, f, now, random)
        assertEquals("Νίκος", pending.requests.single().holder)
        assertEquals(HeirStatus("need-more", planId, s("owner"), 2, 1, pending.requests[0].requestId, missing = 1),
            HeirFlow.requestStatus(f, packages.take(1), identity, now))
        val waiting = HeirFlow.requestStatus(f, two, identity, now + HeirFlow.DAY)
        assertEquals("waiting", waiting.state)
        assertEquals(6, waiting.daysLeft)
        assertEquals(6, assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, two, identity, now + HeirFlow.DAY) }.daysLeft)
        val after = now + 7 * HeirFlow.DAY
        assertEquals("no-backup", HeirFlow.requestStatus(f, two, identity, after).state)
        descriptor(folder)
        assertEquals("ready", HeirFlow.requestStatus(f, two, identity, after).state)
        assertContentEquals(hex("entropy"), HeirFlow.recoverEntropy(f, two, identity, after))
    }

    /** A backup descriptor signed by the plan key, locked to [backupPublic] and written at [writtenAt]. */
    private fun ownDescriptor(folder: MemoryFolder, backupPublic: ByteArray, writtenAt: Long, tag: String) {
        val payload = linkedMapOf<String, JsonValue>(
            "kind" to JsonValue.Str(HeirFlow.BACKUP_KIND), "plan_id" to JsonValue.Str(planId),
            "file" to JsonValue.Str("backup-20270116-080000-$tag.lgk"), "size" to JsonValue.Int(4096),
            "sha256" to JsonValue.Str("ab".repeat(32)), "written_at" to JsonValue.Int(writtenAt),
            "backup_public" to JsonValue.Str(Envelope.b64e(backupPublic)),
        )
        val data = Envelope.seal(Heir.FORMAT, Heir.VERSION, "00000000-0000-4000-8000-0000000000${tag.take(2)}", "", payload, hex("signing_seed"))
        folder.files["$dir/backup-20270116-080000-$tag.lgkheirbackup"] = data
    }

    /** Two shards, a request and the waiting period over: everything but the backup. */
    private fun waitedOut(folder: MemoryFolder): Long {
        val f = HeirFolder(folder)
        HeirFlow.requestAccess(f, packages[0], identity, created + 100, random)
        return created + 100 + 7 * HeirFlow.DAY
    }

    @Test fun without_a_backup_newer_than_the_plan_nothing_is_revealed() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        val after = waitedOut(folder)
        assertEquals("no-backup", HeirFlow.requestStatus(f, packages.take(2), identity, after).state)
        assertEquals("no-backup", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(2), identity, after) }.reason)
        // The right key, but older than the plan (a backup from before the phrase was replaced): still nothing.
        ownDescriptor(folder, hex("backup_public"), created - 1, "0a0b0c0d")
        assertEquals("no-backup", HeirFlow.requestStatus(f, packages.take(2), identity, after).state)
        assertEquals("no-backup", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(2), identity, after) }.reason)
    }

    @Test fun a_backup_locked_to_another_key_reveals_nothing() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        val after = waitedOut(folder)
        // Newer than the plan and signed by the plan key, but locked to another backup key (the phrase was replaced).
        ownDescriptor(folder, ByteArray(32) { 7 }, created + 10, "1a1b1c1d")
        assertEquals("ready", HeirFlow.requestStatus(f, packages.take(2), identity, after).state)
        assertEquals("no-backup", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(2), identity, after) }.reason)
        // The owner's own key opens it.
        ownDescriptor(folder, hex("backup_public"), created + 20, "2a2b2c2d")
        assertContentEquals(hex("entropy"), HeirFlow.recoverEntropy(f, packages.take(2), identity, after))
    }

    @Test fun deny_wins_whatever_its_time_and_a_lost_deny_is_written_again() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        HeirFlow.requestAccess(f, packages[1], identity, created, random)
        val rid = HeirFlow.pendingFor(fresh, f, created, random).requests.single().requestId
        // The owner's clock is 50 years ahead: the deny still wins.
        HeirFlow.deny(fresh, f, rid, created + 50L * 365 * HeirFlow.DAY, random)
        descriptor(folder)
        val later = created + 30 * HeirFlow.DAY
        assertEquals("denied", HeirFlow.requestStatus(f, packages.take(2), identity, later).state)
        assertEquals("denied", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(2), identity, later) }.reason)
        assertTrue(HeirFlow.pendingFor(fresh, f, created, random).requests.isEmpty())
        // Deleted from the folder: the owner's plan remembers the refusal and writes it again.
        folder.files.remove("$dir/deny-$rid${HeirFlow.DENY_SUFFIX}")
        assertEquals("ready", HeirFlow.requestStatus(f, packages.take(2), identity, later).state)
        val remembered = Heir.parsePlan(Heir.withDenied(v.getValue("synced") as JsonValue.Obj, rid))
        assertTrue(HeirFlow.pendingFor(remembered, f, created, random).requests.isEmpty())
        assertTrue(folder.files.containsKey("$dir/deny-$rid${HeirFlow.DENY_SUFFIX}"))
        assertEquals("denied", HeirFlow.requestStatus(f, packages.take(2), identity, later).state)
        // A deny by any other key is ignored.
        val other = MemoryFolder()
        HeirFlow.requestAccess(HeirFolder(other), packages[1], identity, created, random)
        val rid2 = HeirFlow.pendingFor(fresh, HeirFolder(other), created, random).requests.single().requestId
        val forger = planWith {
            it["signing_key"] = JsonValue.Str(Envelope.b64e(ByteArray(32) { 3 }))
            it["signer"] = JsonValue.Str(Envelope.b64e(app.localgatekeys.core.primitives.Ed25519.publicKey(ByteArray(32) { 3 })))
        }
        HeirFlow.deny(forger, HeirFolder(other), rid2, created, random)
        assertEquals("waiting", HeirFlow.requestStatus(HeirFolder(other), packages.take(2), identity, created).state)
    }

    @Test fun requests_without_a_shard_of_this_plan_are_not_listed() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        // A shard with a wrong share, signed by the plan key: its proof does not match the stored holder key.
        val bad = Vectors.hex(v.getValue("shares").arr()[2].str()).also { it[3] = (it[3].toInt() xor 1).toByte() }
        val forged = Heir.sealPackage(planId, bad, "Ben", 2, 3, 7, created, hex("check_salt"), hex("check"), s("owner"),
            "3ebf9c51-405d-4b8a-bf6e-2d3c4b5a6f74", hex("signing_seed"))
        HeirFlow.requestAccess(f, forged, identity, created, random)
        folder.files["$dir/request-00000000-0000-4000-8000-000000000000.lgkheirreq"] = "junk".toByteArray()
        repeat(600) { folder.files["$dir/request-0000%04x-0000-4000-8000-000000000000.lgkheirreq".format(it + 1)] = "{}".toByteArray() }
        HeirFlow.requestAccess(f, packages[0], identity, created, random)
        val listed = HeirFlow.pendingFor(fresh, f, created, random)
        assertEquals(listOf("Νίκος"), listed.requests.map { it.holder })
        assertFalse(listed.flooded)
    }

    @Test fun a_stale_plan_deletes_its_backups_so_old_shards_open_nothing() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        val after = waitedOut(folder)
        descriptor(folder)
        val file = "$dir/${sub("descriptor").getValue("file").str()}".removeSuffix(HeirFlow.DESCRIPTOR_SUFFIX) + HeirFlow.BACKUP_SUFFIX
        folder.files[file] = ByteArray(8)
        folder.files["$dir/backup-notes.txt"] = ByteArray(1)
        assertContentEquals(hex("entropy"), HeirFlow.recoverEntropy(f, packages.take(2), identity, after))
        HeirFlow.pendingFor(fresh, f, after, random) // a current plan keeps its backups
        assertTrue(file in folder.files)
        val stale = planWith { it["stale"] = JsonValue.Bool(true); it["denied"] = JsonValue.Arr(emptyList()) }
        HeirFlow.pendingFor(stale, f, after, random)
        assertEquals(listOf("$dir/backup-notes.txt"), folder.files.keys.filter { it.startsWith("$dir/backup-") })
        assertEquals("no-backup", HeirFlow.requestStatus(f, packages.take(2), identity, after).state)
        assertEquals("no-backup", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(2), identity, after) }.reason)
    }

    @Test fun grant_now_opens_access_early_with_one_shard() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        HeirFlow.requestAccess(f, packages[2], identity, created, random)
        val rid = HeirFlow.pendingFor(fresh, f, created, random).requests.single().requestId
        assertEquals("wrong-phrase", assertFailsWith<HeirFlowException> { HeirFlow.grantNow(fresh, f, rid, "abandon ".repeat(23) + "art", created, random) }.reason)
        assertEquals("wrong-phrase", assertFailsWith<HeirFlowException> { HeirFlow.grantNow(fresh, f, rid, "not a phrase", created, random) }.reason)
        val path = HeirFlow.grantNow(fresh, f, rid, s("phrase"), created, random)
        assertTrue(path.endsWith("grant-$rid${HeirFlow.GRANT_SUFFIX}"))
        assertFalse(String(folder.files.getValue(path)).contains(s("entropy")))
        assertTrue(HeirFlow.pendingFor(fresh, f, created, random).requests.single().granted)
        descriptor(folder)
        val status = HeirFlow.requestStatus(f, packages.subList(2, 3), identity, created + 60)
        assertEquals("ready", status.state)
        assertTrue(status.granted)
        assertContentEquals(hex("entropy"), HeirFlow.recoverEntropy(f, packages.subList(2, 3), identity, created + 60))
        // Usable only by the requester it names.
        val other = RequesterIdentity(ByteArray(32) { 5 }, ByteArray(32) { 6 })
        assertEquals("none", HeirFlow.requestStatus(f, packages.subList(2, 3), other, created + 60).state)
        // A denied request cannot be granted, and a deny beats an earlier grant.
        HeirFlow.deny(fresh, f, rid, created, random)
        assertEquals("denied", assertFailsWith<HeirFlowException> { HeirFlow.grantNow(fresh, f, rid, s("phrase"), created, random) }.reason)
        assertEquals("denied", HeirFlow.requestStatus(f, packages.subList(2, 3), identity, created + 60).state)
        // A stale plan grants nothing.
        val g2 = MemoryFolder()
        HeirFlow.requestAccess(HeirFolder(g2), packages[2], identity, created, random)
        val rid2 = HeirFlow.pendingFor(fresh, HeirFolder(g2), created, random).requests.single().requestId
        val stale = planWith { it["stale"] = JsonValue.Bool(true); it["denied"] = JsonValue.Arr(emptyList()) }
        assertEquals("stale-plan", assertFailsWith<HeirFlowException> { HeirFlow.grantNow(stale, HeirFolder(g2), rid2, s("phrase"), created, random) }.reason)
        assertEquals("no-request", assertFailsWith<HeirFlowException> { HeirFlow.grantNow(fresh, HeirFolder(g2), "11111111-2222-4333-8444-555555555555", s("phrase"), created, random) }.reason)
    }

    @Test fun a_grant_with_the_wrong_secret_stops_at_the_hkdf_check() {
        val folder = MemoryFolder()
        val f = HeirFolder(folder)
        HeirFlow.requestAccess(f, packages[0], identity, created, random)
        val request = HeirFlow.pendingFor(fresh, f, created, random).requests.single()
        val wrong = ByteArray(32) { 0x42 }
        folder.files["$dir/grant-${request.requestId}${HeirFlow.GRANT_SUFFIX}"] =
            HeirFlow.grantBytes(plan, request, wrong, created, ByteArray(32) { 7 }, "4fc0ad62-516e-4c9b-80f7-3e4d5c6b7a85")
        descriptor(folder)
        assertEquals("ready", HeirFlow.requestStatus(f, packages.take(1), identity, created).state)
        assertEquals("check-failed", assertFailsWith<HeirFlowException> { HeirFlow.recoverEntropy(f, packages.take(1), identity, created) }.reason)
    }

    @Test fun the_picked_folder_may_be_the_emergency_folder() {
        assertEquals(dir, HeirFlow.planDir(HeirFolder(MemoryFolder()), planId))
        assertEquals(planId, HeirFlow.planDir(HeirFolder(MemoryFolder(), HeirFlow.FOLDER_NAME), planId))
        val folder = MemoryFolder()
        val path = HeirFlow.requestAccess(HeirFolder(folder, HeirFlow.FOLDER_NAME), packages[0], identity, created, random)
        assertTrue(path.startsWith("$planId/request-"))
        assertEquals(1, HeirFlow.pendingFor(fresh, HeirFolder(folder, HeirFlow.FOLDER_NAME), created, random).requests.size)
    }

    @Test fun heir_file_names() {
        for (name in listOf("LocalGateKeys Emergency", "a.lgkheir", "request-x.lgkheirreq", "backup-20270115-080000-0a1b2c3d.lgk", "x.lgkheirbackup")) {
            assertTrue(HeirFlow.isHeirFile(name), name)
        }
        for (name in listOf("backup.lgk", "device.lgksync", "backup-2027-0a1b2c3d.lgk")) assertFalse(HeirFlow.isHeirFile(name), name)
    }

    @Test fun requester_identity_record_is_strict() {
        val r = RequesterIdentity.generate(random)
        val back = RequesterIdentity.fromRecord(r.toRecord())
        assertContentEquals(r.signer, back.signer)
        assertContentEquals(r.boxPublic, back.boxPublic)
        for (bad in listOf(JsonValue.Null, JsonValue.Obj(mapOf("version" to JsonValue.Int(2))), JsonValue.Obj(r.toRecord().fields + ("x" to JsonValue.Int(1))))) {
            assertFailsWith<HeirFlowException> { RequesterIdentity.fromRecord(bad) }
        }
    }
}
