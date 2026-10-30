package app.localgatekeys.core.sync

import app.localgatekeys.core.group.SyncFormatException
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors.A
import app.localgatekeys.core.support.MergeVectors.B
import app.localgatekeys.core.support.MergeVectors.C
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.SyncFixtures.INSTALL
import app.localgatekeys.core.support.SyncFixtures.T0
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.SyncFixtures.epochKey
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Rollback witnesses (plan 2026-10-22 "Part B update (2026-10-29)"): the shared vectors under
 * `tests/vectors/sync/witness/`, the pure rule, the folder transport and the acknowledgement. Mirrors the desktop
 * `test_sync_witness.py`, `test_sync_rollback_ack.py`, the witness cases of `test_sync_folder_transport.py` and
 * `test_sync_vectors.py`.
 */
class WitnessTest {
    private fun issues(r: RunReport) = r.issues.map { it.kind }

    private fun long(v: JsonValue?): Long = (v as JsonValue.Int).v

    private fun longs(v: JsonValue?): Map<String, Long> = obj(v).mapValues { long(it.value) }

    private fun reason(body: () -> Any?): String = try {
        body()
        "valid"
    } catch (e: SyncFormatException) {
        e.reason
    }

    // ---- shared vectors ----

    @Test
    fun cases_json_headers_matches_and_checks() {
        val cases = Vectors.json(Vectors.sync("witness/cases.json")).obj().fields
        val k = obj(cases["constants"])
        assertEquals(ViewFile.FORMAT_WITNESS, long(k["FORMAT_WITNESS"]))
        assertEquals(ViewFile.MAX_WITNESS.toLong(), long(k["MAX_WITNESS"]))
        assertEquals(Witness.MAX_WITNESS_BYTES.toLong(), long(k["MAX_WITNESS_BYTES"]))
        val gk = epochKey("1")
        val outcomes = HashSet<String>()
        for (c in arr(cases["headers"]).map { obj(it) }) {
            val got = reason { ViewFile.decode(Base64Std.decodeStrict(str(c["file_b64"])!!), gk, null) }
            assertEquals(str(c["expected"]), got, str(c["name"]))
            outcomes.add(got)
        }
        assertEquals(setOf("valid", "bad-header"), outcomes)
        val viewA = ViewFile.decode(SyncFixtures.deviceBytes("A"), gk, A).first
        val matched = ArrayList<String>()
        for (c in arr(cases["witness_file_matches"]).map { obj(it) }) {
            val side = ViewFile.decode(Base64Std.decodeStrict(str(c["witness_file_b64"])!!), gk, null)
            val obs = Witness.observation(viewA, side)
            val want = c["expected"]
            if (want == JsonValue.Null) {
                assertNull(obs, str(c["name"]))
            } else {
                val w = obj(want)
                assertEquals(Observation(str(w["peer_id"])!!, long(w["vault_generation"]), longs(w["witness"])), obs, str(c["name"]))
                matched.add(str(c["name"])!!)
            }
        }
        assertEquals(listOf("matches"), matched)
        val kinds = HashSet<String>()
        for (c in arr(cases["checks"]).map { obj(it) }) {
            val name = str(c["name"])
            val observations = arr(c["observations"]).map { o ->
                val f = obj(o)
                Observation(str(f["peer_id"])!!, long(f["vault_generation"]), longs(f["witness"]))
            }
            val res = Witness.check(
                str(c["own_id"])!!, long(c["own_generation"]), observations, longs(c["peer_generations"]), long(c["rollback_suspected"]),
            )
            val e = obj(c["expected"])
            val wantIssues = arr(e["issues"]).map { i -> arr(i).map { str(it)!! } }
            assertEquals(wantIssues, res.issues.map { listOf(it.kind, it.detail) }, name)
            assertEquals(longs(e["peer_generations"]), res.peerGenerations, name)
            assertEquals(long(e["rollback_suspected"]), res.rollbackSuspected, name)
            assertEquals(arr(e["capable"]).map { str(it)!! }, res.capable.sorted(), name)
            kinds.addAll(res.issues.map { it.kind })
        }
        assertEquals(setOf("peer-vault-rollback", "vault-rollback"), kinds)
    }

    @Test
    fun format2_device_views_carry_the_documented_generations_and_witnesses() {
        val gk = epochKey("1")
        val ids = mapOf("A" to A, "B" to B, "C" to C)
        val gens = mapOf("A" to 40L, "B" to 12L, "C" to 9L)
        val seen = mapOf("A" to mapOf(B to 12L), "B" to mapOf(A to 40L), "C" to emptyMap())
        for ((name, id) in ids) {
            val v1 = ViewFile.decode(SyncFixtures.deviceBytes(name), gk, id)
            val v2 = ViewFile.decode(Vectors.sync("witness/devices_v2/$name.lgksync").readBytes(), gk, id)
            assertEquals(1L, v1.first.format)
            assertEquals(2L, v2.first.format)
            assertEquals(gens[name], v2.first.vaultGeneration)
            assertEquals(seen[name], v2.first.witness)
            assertEquals(v1.second, v2.second)
            assertEquals(v1.first.copy(format = 2, vaultGeneration = gens[name], witness = seen[name]!!), v2.first)
            assertEquals(Observation(id, gens[name]!!, seen[name]!!), Witness.observation(v2.first))
            assertNull(Witness.observation(v1.first))
        }
    }

    @Test
    fun sidecar_witness_file_belongs_to_the_format1_view_of_A() {
        val gk = epochKey("1")
        val view = ViewFile.decode(SyncFixtures.deviceBytes("A"), gk, A).first
        val raw = Vectors.sync("witness/sidecar/A.lgksync").readBytes()
        val side = ViewFile.decode(raw, gk, A, maxBytes = Witness.MAX_WITNESS_BYTES, maxRecords = 0)
        val sig = Vectors.sync("witness/sidecar/A.lgksig").readBytes()
        assertEquals(
            Base64Std.encode(SyncFixtures.identity("A").signingPublicKey), Base64Std.encode(ViewSignature.verify(sig, raw, side.first)),
        )
        assertEquals(Observation(A, 40, mapOf(B to 12L, C to 9L)), Witness.observation(view, side))
    }

    // ---- view format 2 ----

    @Test
    fun format2_round_trip_and_header_rules() {
        val gk = epochKey("1")
        val clock = FixedClock(T0)
        val raw = ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("v2"), vaultGeneration = 5, witness = mapOf(B to 4L))
        val back = ViewFile.decode(raw, gk, A).first
        assertEquals(2L, back.format)
        assertEquals(5L, back.vaultGeneration)
        assertEquals(mapOf(B to 4L), back.witness)
        // Without a generation: format 1, byte for byte as before.
        val v1 = ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("v1"))
        assertEquals(1L, ViewFile.decodeHeader(v1).format)
        assertEquals("bad-header", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), witness = emptyMap()) })
        assertEquals("bad-header", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), vaultGeneration = 1, witness = mapOf(A to 1L)) })
        assertEquals("bad-header", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), vaultGeneration = -1) })
        assertEquals("bad-header", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), vaultGeneration = 1L shl 53) })
        val many = (0 until 65).associate { "d$it" to 1L }
        assertEquals("bad-header", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), vaultGeneration = 1, witness = many) })
        assertEquals("valid", reason { ViewFile.encode(gk, A, 3, emptyList(), clock, DetRand("x"), vaultGeneration = 1, witness = many.entries.take(64).associate { it.key to it.value }) })
        // A witness file holds no records.
        val withRecords = ViewFile.encode(gk, A, 3, SyncFixtures.views()[0].states, clock, DetRand("r"), vaultGeneration = 1)
        assertEquals("too-many-records", reason { ViewFile.decode(withRecords, gk, A, maxRecords = 0) })
    }

    // ---- the pure rule ----

    @Test
    fun suspicion_is_sticky_and_an_implausible_witness_is_not() {
        val far = Witness.check(A, 10, listOf(Observation(B, 5, mapOf(A to 10 + Witness.MAX_WITNESS_JUMP + 1))), emptyMap(), 0)
        assertEquals(listOf("witness-implausible"), far.issues.map { it.kind })
        assertEquals(0L, far.rollbackSuspected)
        val edge = Witness.check(A, 10, listOf(Observation(B, 5, mapOf(A to 10 + Witness.MAX_WITNESS_JUMP))), emptyMap(), 0)
        assertEquals(listOf("vault-rollback"), edge.issues.map { it.kind })
        // Sticky: reported on a run without observations, even with the own generation past it.
        val later = Witness.check(A, 1_000_000, emptyList(), edge.peerGenerations, edge.rollbackSuspected)
        assertEquals(listOf(SyncIssue("vault-rollback", "")), later.issues)
        // The own id is ignored; equal is fine.
        val own = Witness.check(A, 3, listOf(Observation(A, 1, mapOf(B to 9L)), Observation(B, 5)), mapOf(B to 5L), 0)
        assertEquals(emptyList(), own.issues)
        assertEquals(setOf(B), own.capable)
    }

    @Test
    fun own_witness_and_prune_keep_members_only_at_most_64() {
        val gens = (0 until 70).associate { "d%02d".format(it) to it.toLong() } + (A to 1L) + ("x" to (1L shl 60))
        val w = Witness.ownWitness(gens, gens.keys, A)
        assertEquals(64, w.size)
        assertFalse(A in w)
        assertEquals((0 until 64).map { "d%02d".format(it) }, w.keys.toList())
        assertEquals(mapOf("x" to Witness.MAX_GENERATION), Witness.ownWitness(gens, setOf("x"), A))
        assertEquals(mapOf("d01" to 1L), Witness.prune(gens, setOf("d01", "zz")))
    }

    // ---- LAN save throttle and flush (desktop apply_witness / flush_witness) ----

    private fun lanState(): SyncGroupState = SyncGroupState(
        SyncFixtures.epochKey("1").groupId, 1, ByteArray(32), SyncFixtures.identity("C"), INSTALL, hasFolder = false,
    )

    @Test
    fun lan_saves_new_peers_at_once_and_rises_at_most_every_ten_minutes() {
        val mem = WitnessMemory()
        var state = lanState()
        val peers = listOf(A)
        val (i1, s1) = Witness.applyLan(state, 3, listOf(Observation(A, 10)), mem, peers, 1000)
        assertEquals(emptyList(), i1)
        state = assertNotNull(s1) // a new peer and a new capability: saved
        assertEquals(mapOf(A to 10L), state.peerGenerations)
        assertEquals(listOf(A), state.witnessPeers)
        mem.markSaved(state.peerGenerations.keys, 1000)
        val (_, s2) = Witness.applyLan(state, 3, listOf(Observation(A, 11)), mem, peers, 1000 + 599)
        assertNull(s2) // a rise inside the interval: memory only
        assertEquals(mapOf(A to 11L), mem.merged(state))
        // The memory is what the next check uses: a drop to 10 is a rollback although 10 is stored.
        val (i3, _) = Witness.applyLan(state, 3, listOf(Observation(A, 10)), mem, peers, 1000 + 599)
        assertEquals(listOf("peer-vault-rollback"), i3.map { it.kind })
        val (_, s4) = Witness.applyLan(state, 3, listOf(Observation(A, 12)), mem, peers, 1000 + 600)
        assertEquals(mapOf(A to 12L), assertNotNull(s4).peerGenerations)
        mem.markSaved(s4.peerGenerations.keys, 1000 + 600)
        // Flush: the in-memory value above the stored one.
        val (_, s5) = Witness.applyLan(s4, 3, listOf(Observation(A, 13)), mem, peers, 1000 + 601)
        assertNull(s5)
        assertEquals(mapOf(A to 13L), assertNotNull(mem.flush(s4, peers)).peerGenerations)
        assertNull(mem.flush(s4.copy(peerGenerations = mapOf(A to 13L)), peers))
        // A suspicion is saved at once.
        val (i6, s6) = Witness.applyLan(s4, 3, listOf(Observation(A, 13, mapOf(SyncFixtures.identity("C").deviceId to 7L))), mem, peers, 1000 + 602)
        assertEquals(listOf("vault-rollback"), i6.map { it.kind })
        assertEquals(7L, assertNotNull(s6).rollbackSuspected)
    }

    @Test
    fun two_refusals_in_a_row_drop_format2_support() {
        val mem = WitnessMemory()
        val state = lanState().copy(witnessPeers = listOf(A))
        assertEquals(1, mem.refused(state, A))
        mem.clearRefusals(A) // a good format-2 exchange in between
        assertEquals(1, mem.refused(state, A))
        assertEquals(2, mem.refused(state, A))
        val (_, dropped) = Witness.applyLan(state, 3, emptyList(), mem, listOf(A), 0, dropCapable = A)
        assertEquals(emptyList(), assertNotNull(dropped).witnessPeers)
    }

    // ---- folder transport ----

    private class Joined(val folder: MemoryFolder, val store: MemoryStore, val fs: FolderSync) {
        val own: String get() = store.snapshot.sync!!.deviceId
    }

    private fun joined(): Joined {
        val folder = SyncFixtures.seededFolder(signed = true)
        val store = MemoryStore()
        val fs = FolderSync(folder, INSTALL)
        val pw = SyncFixtures.pwKey("1")
        val r = fs.join(store, "Pixel", DetRand("witness|join"), FixedClock(T0 + 1000)) { pw }
        assertEquals(emptyList(), issues(r))
        return Joined(folder, store, fs)
    }

    private val counters = mapOf("A" to 7L, "B" to 4L, "C" to 3L)
    private val idOf = mapOf("A" to A, "B" to B, "C" to C)

    /** [who]'s signed witness file for its view at [counter] (default: the seeded one). */
    private fun putWitness(j: Joined, who: String, generation: Long, witness: Map<String, Long>, counter: Long = counters[who]!!) {
        val id = idOf[who]!!
        val raw = ViewFile.encode(epochKey("1"), id, counter, emptyList(), FixedClock(T0 + 900), DetRand("w|$who|$generation"), vaultGeneration = generation, witness = witness)
        j.folder.files[FolderLayout.witnessFile(id)!!] = raw
        j.folder.files[FolderLayout.witnessSignatureFile(id)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity(who))
    }

    /** A new signed format-1 view of A at [counter] (same states). */
    private fun rewriteA(j: Joined, counter: Long) {
        val states = ViewFile.decode(j.folder.files[devPath(A)]!!, epochKey("1"), A).second
        val raw = ViewFile.encode(epochKey("1"), A, counter, states, FixedClock(T0 + 950), DetRand("a|$counter"))
        j.folder.files[devPath(A)] = raw
        j.folder.files[FolderLayout.signatureFile(A)!!] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity("A"))
    }

    private var tick = 0L

    private fun run(j: Joined, memory: WitnessMemory? = null): RunReport {
        tick += 10
        return j.fs.runOnce(j.store, DetRand("witness|run|$tick"), FixedClock(T0 + 1000 + tick), memory)
    }

    @Test
    fun own_view_stays_format1_with_a_signed_witness_file_while_peers_are_older() {
        val j = joined()
        val gk = epochKey("1")
        val view = ViewFile.decode(j.folder.files[devPath(j.own)]!!, gk, j.own)
        assertEquals(1L, view.first.format)
        val raw = assertNotNull(j.folder.files[FolderLayout.witnessFile(j.own)!!])
        val side = ViewFile.decode(raw, gk, j.own, maxRecords = 0)
        val sig = j.folder.files[FolderLayout.witnessSignatureFile(j.own)!!]!!
        assertEquals(
            Base64Std.encode(j.store.snapshot.sync!!.identity.signingPublicKey),
            Base64Std.encode(ViewSignature.verify(sig, raw, side.first)),
        )
        val obs = assertNotNull(Witness.observation(view.first, side))
        assertEquals(Witness.generation(j.store.snapshot)!! - 1, obs.vaultGeneration) // published before the run's commit
        assertTrue(obs.vaultGeneration >= 1)
        // Nothing changed: no rewrite on the next run, although committing raised the generation.
        val writes = j.folder.writes.size
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(writes, j.folder.writes.size)
    }

    @Test
    fun a_peer_witness_above_this_vault_is_vault_rollback_until_acknowledged() {
        val j = joined()
        putWitness(j, "A", 40, mapOf(j.own to 500L))
        assertEquals(listOf("vault-rollback"), issues(run(j)))
        val st = j.store.snapshot.sync!!
        assertEquals(500L, st.rollbackSuspected)
        assertEquals(40L, st.peerGenerations[A])
        assertEquals(listOf(A), st.witnessPeers)
        assertEquals(7L, st.witnessCounters[A])
        // Sticky: the next run (A's witness unchanged) reports it again; no automatic acknowledgement.
        assertEquals(listOf("vault-rollback"), issues(run(j)))
        // "This was me": generation above every witness, warning cleared in one commit.
        assertTrue(Witness.acknowledgeVaultRollback(j.store))
        assertEquals(0L, j.store.snapshot.sync!!.rollbackSuspected)
        assertTrue(Witness.generation(j.store.snapshot)!! >= 501)
        assertFalse(Witness.acknowledgeVaultRollback(j.store))
        assertEquals(emptyList(), issues(run(j)))
    }

    @Test
    fun an_implausible_witness_is_reported_and_never_stored() {
        val j = joined()
        putWitness(j, "A", 40, mapOf(j.own to Witness.MAX_GENERATION))
        assertEquals(listOf("witness-implausible"), issues(run(j)))
        assertEquals(0L, j.store.snapshot.sync!!.rollbackSuspected)
        putWitness(j, "A", 40, emptyMap())
        assertEquals(emptyList(), issues(run(j)))
    }

    @Test
    fun a_peer_publishing_a_lower_generation_is_peer_vault_rollback() {
        val j = joined()
        putWitness(j, "A", 40, emptyMap())
        assertEquals(emptyList(), issues(run(j)))
        putWitness(j, "A", 30, emptyMap())
        val r = run(j)
        assertEquals(listOf(SyncIssue("peer-vault-rollback", A)), r.issues)
        assertEquals(40L, j.store.snapshot.sync!!.peerGenerations[A]) // never lowered
        assertTrue(Witness.forgetPeerGeneration(j.store, A))
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(30L, j.store.snapshot.sync!!.peerGenerations[A])
    }

    @Test
    fun a_witnessing_peer_without_a_witness_file_is_witness_missing_after_one_grace_run() {
        val j = joined()
        putWitness(j, "A", 40, emptyMap())
        assertEquals(emptyList(), issues(run(j)))
        rewriteA(j, 8) // a newer signed view, its witness file not (yet) uploaded
        assertEquals(emptyList(), issues(run(j))) // grace: a cloud client may upload it after the view
        assertEquals(listOf(SyncIssue("witness-missing", A)), run(j).issues)
        putWitness(j, "A", 41, emptyMap(), counter = 8)
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(8L, j.store.snapshot.sync!!.witnessCounters[A])
        // A bad signature counts as missing (silently skipped, then reported).
        rewriteA(j, 9)
        putWitness(j, "A", 42, emptyMap(), counter = 9)
        val wpath = FolderLayout.witnessSignatureFile(A)!!
        val raw = j.folder.files[FolderLayout.witnessFile(A)!!]!!
        j.folder.files[wpath] = ViewSignature.sign(raw, ViewFile.decodeHeader(raw), SyncFixtures.identity("B"))
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(listOf("witness-missing"), issues(run(j)))
    }

    @Test
    fun own_view_turns_format2_once_every_member_supports_it() {
        val j = joined()
        putWitness(j, "A", 40, emptyMap())
        putWitness(j, "B", 12, emptyMap())
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(1L, ViewFile.decodeHeader(j.folder.files[devPath(j.own)]!!).format) // C has not shown support
        putWitness(j, "C", 9, emptyMap())
        val counterBefore = j.store.snapshot.sync!!.ownCounter
        assertEquals(emptyList(), issues(run(j)))
        val header = ViewFile.decodeHeader(j.folder.files[devPath(j.own)]!!)
        assertEquals(2L, header.format)
        assertEquals(mapOf(A to 40L, B to 12L, C to 9L), header.witness)
        assertEquals(counterBefore + 1, j.store.snapshot.sync!!.ownCounter)
        // Settled: no rewrite on a generation change alone.
        val writes = j.folder.writes.size
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(writes, j.folder.writes.size)
    }

    @Test
    fun a_deleted_own_witness_file_is_written_again_alone() {
        val j = joined()
        val counter = j.store.snapshot.sync!!.ownCounter
        val viewBefore = j.folder.files[devPath(j.own)]!!.toList()
        j.folder.files.remove(FolderLayout.witnessFile(j.own)!!)
        val writes = j.folder.writes.size
        assertEquals(emptyList(), issues(run(j)))
        assertEquals(
            listOf(FolderLayout.witnessFile(j.own)!!, FolderLayout.witnessSignatureFile(j.own)!!),
            j.folder.writes.drop(writes),
        )
        assertEquals(counter, j.store.snapshot.sync!!.ownCounter)
        assertEquals(viewBefore, j.folder.files[devPath(j.own)]!!.toList())
        val side = ViewFile.decode(j.folder.files[FolderLayout.witnessFile(j.own)!!]!!, epochKey("1"), j.own, maxRecords = 0)
        assertEquals(counter, side.first.counter)
    }

    @Test
    fun folder_checks_use_the_session_memory() {
        val j = joined()
        val mem = WitnessMemory()
        mem.remember(j.store.snapshot.sync!!, mapOf(A to 50L)) // a LAN exchange checked 50 (not saved yet)
        putWitness(j, "A", 45, emptyMap())
        assertEquals(listOf(SyncIssue("peer-vault-rollback", A)), run(j, mem).issues)
        assertEquals(50L, j.store.snapshot.sync!!.peerGenerations[A])
    }
}
