package app.localgatekeys.android.sync

import app.localgatekeys.android.sync.SyncCoordinator.Phase
import app.localgatekeys.android.sync.SyncCoordinator.Trigger
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.Slot
import app.localgatekeys.android.vault.VaultCounterStore
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.Enrollment
import app.localgatekeys.core.lan.LanAddress
import app.localgatekeys.core.lan.LanEndpoint
import app.localgatekeys.core.lan.LanSyncException
import app.localgatekeys.core.lan.LanTransportException
import app.localgatekeys.core.lan.PairingOffer
import app.localgatekeys.core.lan.PinnedPeer
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Port of `ios/LocalGateKeysTests/SyncCoordinatorTests.swift` (the coordinator part; `PairedConnectorTests` belong to
 * the socket transport, Task 11). The coordinator is confined to its scope's thread like the iPhone's @MainActor:
 * each test runs on runBlocking's event loop and hands the coordinator a scope on that loop.
 */
class SyncCoordinatorTest {
    @get:Rule val tmp = TemporaryFolder()

    private lateinit var slots: SecretSlots
    private lateinit var lan: FakeLan
    private lateinit var folder: MemoryFolder
    private lateinit var folders: FakeFolders
    private lateinit var autoFill: CountingAutoFill
    private lateinit var clock: TestClock
    private lateinit var sleeper: NoSleep
    private val scopes = ArrayList<CoroutineScope>()
    private val created = ArrayList<SyncCoordinator>()

    @Before fun setUp() {
        slots = SecretSlots(tmp.newFile("secrets.bin").also { it.delete() }, ByteArray(32) { 3 }, SystemRandomSource())
        lan = FakeLan(); folder = MemoryFolder(); folders = FakeFolders(folder)
        autoFill = CountingAutoFill(); clock = TestClock(SyncVectors.lanNow()); sleeper = NoSleep()
    }

    @After fun tearDown() {
        created.forEach { it.shutdown() }
        scopes.forEach { it.cancel() }
    }

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(60_000) { body() } }

    /** A coordinator on the test's event loop (its "main thread"). */
    private fun CoroutineScope.coordinator(store: ItemStore, deps: SyncDependencies = deps()): SyncCoordinator {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        return SyncCoordinator(store, deps, scope).also { created.add(it) }
    }

    private fun deps(identity: DeviceIdentity? = null): SyncDependencies {
        var d = SyncDependencies(
            slots = slots, folders = folders, lan = lan, autoFill = autoFill, random = SystemRandomSource(), clock = clock,
            licenseKeys = emptyMap(), sleep = sleeper.fn, deviceName = SyncVectors.DEVICE_NAME,
        )
        if (identity != null) d = d.copy(newIdentity = { identity })
        return d
    }

    private suspend fun until(what: String = "condition", cond: () -> Boolean) {
        try {
            withTimeout(20_000) { while (!cond()) delay(1) }
        } catch (e: Exception) {
            throw AssertionError("timed out waiting for $what", e)
        }
    }

    private suspend fun settle(rounds: Int = 50) {
        repeat(rounds) { yield(); delay(1) }
    }

    /** The desktop's inviter (A) side of the vector enrollment: checks B's request, answers with the recorded reply. */
    private fun inviterAnswers() {
        val offer = PairingOffer.parseQr(SyncVectors.qrText())
        val a = SyncVectors.identity("A")
        val reply = SyncVectors.data("lan/enroll_reply_no_endpoint.bin")
        lan.enrollReply = { request ->
            val opened = Enrollment.openRequest(offer, a, request)
            assertNull(opened.endpoint) // a phone announces no endpoint
            reply
        }
    }

    /** A phone joined by QR (vector group, identity B, paired with A at the offer endpoint). */
    private suspend fun CoroutineScope.qrJoined(store: LockedStore): SyncCoordinator {
        inviterAnswers()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        val ok = c.joinByQr(SyncVectors.qrText())
        assertTrue(c.actionError.value ?: "", ok)
        return c
    }

    /**
     * The epoch-1 folder as apps before keyring format 2 left it (Swift `seedEpoch1Folder` on main): `keyring_v1_epoch1.json`
     * (members without signing keys) and unsigned A/B/C views. The format-2 `keyring_epoch1.json` lists every member's
     * signing key, so A/B/C's unsigned views would be refused.
     */
    private fun seedEpoch1Folder() {
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_v1_epoch1.json"))
        for (who in listOf("A", "B", "C")) {
            val id = SyncVectors.identity(who).deviceId
            folder.put("LocalGateKeys Sync/devices/$id.lgksync", SyncVectors.data("devices/$who.lgksync"))
        }
        clock.now = 1_790_000_000 + 1000
    }

    private fun folderUri(): String? = slots.read(Slot.FOLDER_URI)?.toString(Charsets.UTF_8)

    // MARK: AutoFill identities (an Android no-op in the app; the seam keeps the iPhone's order and lock rules)

    @Test fun identity_updates_run_in_order_and_stop_after_shutdown() = test {
        val c = coordinator(LockedStore(StoreSnapshot()))
        c.identitySettingsChanged(); c.identitySettingsChanged()
        c.shutdownAndWait()
        val after = autoFill.calls
        assertTrue(after <= 2)
        c.identitySettingsChanged()
        c.shutdownAndWait()
        assertEquals("nothing republishes after shutdown", after, autoFill.calls)
    }

    @Test fun not_joined_sync_still_publishes_identities() = test {
        val (id, wrapper) = noteRecord(1)
        val store = LockedStore(StoreSnapshot(records = mapOf(id to wrapper), revision = 1))
        val c = coordinator(store)
        c.sync(Trigger.APP_OPEN) // unlock
        assertEquals("unlock publishes the identities even when this phone never joined", 1, autoFill.calls)
        assertEquals(0, lan.exchanges)
    }

    @Test fun local_commit_publishes_identities_at_once_and_never_after_lock() = test {
        val d = deps().copy(sleep = { delay(3_600_000) }) // the debounced sync never fires
        val c = coordinator(LockedStore(), d)
        c.noteLocalEdit()
        c.identitiesSettled()
        assertEquals("an editor save/delete republishes without waiting for sync", 1, autoFill.calls)
        c.noteLocalEdit()
        c.identitiesSettled()
        assertEquals(2, autoFill.calls)
        assertEquals(0, lan.exchanges)
        c.shutdown()
        c.noteLocalEdit()
        c.identitiesSettled()
        assertEquals("nothing republishes after lock", 2, autoFill.calls)
    }

    @Test fun sync_publishes_after_a_queued_identity_update_never_alongside() = test {
        val gated = GatedAutoFill()
        val c = coordinator(LockedStore(), deps().copy(autoFill = gated))
        c.refreshIdentities() // a settings change, held mid-publish
        until("held publish") { gated.waiting == 1 }
        val run = async { c.sync(Trigger.APP_OPEN) } // not joined: the run publishes too
        settle()
        assertEquals("the run's publish waits for the update queued before it", 1, gated.calls)
        gated.release()
        run.await()
        assertEquals(2, gated.calls)
        assertEquals(1, gated.maxConcurrent)
    }

    // MARK: joining

    @Test fun join_by_qr_enrolls_pins_the_inviter_and_runs_the_first_sync() = test {
        val a = SyncVectors.identity("A")
        val (id, wrapper) = noteRecord(1, title = "From PC")
        val fromPC = peerStates(mapOf(id to wrapper), a.deviceId, clock.now)
        lan.exchange = { fromPC }
        val store = LockedStore()
        val c = qrJoined(store)

        val state = store.snapshot.sync!!
        val gk = SyncVectors.lanGroupKey()
        assertEquals(gk.groupId, state.groupId); assertEquals(1L, state.epoch); assertArrayEquals(gk.key, state.key)
        assertEquals(SyncVectors.identity("B").deviceId, state.deviceId)
        assertFalse(state.hasFolder)
        assertEquals(slots.installId(), state.installId)
        val peer = slots.pairedPeer()!!
        assertEquals(PairingOffer.parseQr(SyncVectors.qrText()).inviterPeer, peer)
        assertTrue(LanAddress.isLan(peer.endpoint!!.host))
        // First sync ran: the PC's item arrived through ItemStore, AutoFill was told.
        assertEquals(1, lan.enrolls); assertEquals(1, lan.exchanges)
        assertEquals(wrapper, store.snapshot.records[id])
        assertEquals(1, autoFill.calls)
        assertEquals(Phase.IDLE, c.phase.value); assertTrue(c.membership.value.joined); assertEquals(peer, c.membership.value.peer)
        assertNotNull(c.lastSyncedAt.value); assertEquals(emptyList<SyncWording.IssueView>(), c.issues.value)
        assertEquals("This phone joined the sync group. The first sync is running.", c.actionInfo.value)
    }

    @Test fun qr_refusals_use_desktop_wording_and_leave_store_untouched() = test {
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        c.joinByQr("not a code")
        assertEquals("That is not a valid LocalGateKeys pairing code.", c.actionError.value)
        lan.enrollReply = { throw LanSocketException("connect failed") }
        c.joinByQr(SyncVectors.qrText())
        assertEquals("Could not connect to 192.168.1.20:48201. Check that the PC is on this Wi-Fi and shows its code.", c.actionError.value)
        lan.enrollReply = { Enrollment.REFUSED_MAGIC + """{"reason":"used-or-expired"}""".toByteArray() }
        c.joinByQr(SyncVectors.qrText())
        assertEquals("This pairing code was used up or expired. Show a new code.", c.actionError.value)
        lan.enrollReply = { Enrollment.REFUSED_MAGIC + """{"reason":"full"}""".toByteArray() }
        c.joinByQr(SyncVectors.qrText())
        assertEquals("The other device already has the most paired devices. Remove one there first.", c.actionError.value)
        clock.now = 1_790_000_000 + 10_000 // past the offer's expiry: refused before anything is sent
        val before = lan.enrolls
        c.joinByQr(SyncVectors.qrText())
        assertEquals("This pairing code was used up or expired. Show a new code.", c.actionError.value)
        assertEquals(before, lan.enrolls)
        assertEquals(0, store.commits); assertNull(store.snapshot.sync); assertNull(slots.pairedPeer())
    }

    // MARK: sync v2 (Enrollment version 2: the verification code and the Accept step)

    @Test fun join_shows_the_verification_code_while_the_inviter_waits_for_accept() = test {
        inviterAnswers()
        val c = coordinator(LockedStore(), deps(SyncVectors.identity("B")))
        assertNull(c.verificationCode.value)
        val gate = AsyncGate()
        lan.connectsBeforeHold = true
        lan.enrollHold = { gate.await() } // the PC has not chosen Accept yet
        val join = async { c.joinByQr(SyncVectors.qrText()) }
        until("code") { c.verificationCode.value != null }
        // B's request without an endpoint, named as in the vector: expected_lan.json reply_no_endpoint.verification_code.
        assertEquals("496265", c.verificationCode.value)
        val offer = PairingOffer.parseQr(SyncVectors.qrText())
        assertEquals(Enrollment.verificationCode(offer, SyncVectors.identity("B"), null, SyncVectors.DEVICE_NAME), c.verificationCode.value)
        until("connected hop") { c.connecting.value == null }
        assertEquals(Phase.JOINING, c.phase.value)
        gate.open()
        assertTrue(c.actionError.value ?: "", join.await())
        assertNull(c.verificationCode.value)
    }

    @Test fun the_request_carries_the_phone_name() = test {
        // Global Constraints: the device name sent when joining is the generic "Android phone" (deps default).
        val offer = PairingOffer.parseQr(SyncVectors.qrText())
        var name: String? = null
        lan.enrollReply = { r -> name = Enrollment.openRequest(offer, SyncVectors.identity("A"), r).name; throw LanSocketException("x") }
        val defaults = SyncDependencies(slots = slots, folders = folders, lan = lan, random = SystemRandomSource(), clock = clock, licenseKeys = emptyMap())
        assertEquals(SyncWording.DEVICE_NAME, defaults.deviceName)
        val c = coordinator(LockedStore(), deps(SyncVectors.identity("B")).copy(deviceName = defaults.deviceName))
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertEquals("Android phone", name)
    }

    @Test fun declined_and_update_needed_refusals_use_the_iphone_wording() = test {
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        lan.enrollReply = { Enrollment.REFUSED_MAGIC + """{"reason":"declined"}""".toByteArray() }
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertEquals(
            "The other device declined, or nobody chose Accept there in time. Show a new code there and choose Accept when both screens show the same code.",
            c.actionError.value,
        )
        assertNull(c.verificationCode.value)
        lan.enrollReply = { Enrollment.REFUSED_MAGIC + """{"reason":"update-needed"}""".toByteArray() }
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertEquals("Update LocalGateKeys on this phone to pair with that device.", c.actionError.value)
        assertNull(c.verificationCode.value)
        lan.enrollReply = { Enrollment.REFUSED_MAGIC + """{"reason":"something-new"}""".toByteArray() }
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertEquals("The other device refused the pairing. Show a new code and try again.", c.actionError.value)
        assertEquals(0, store.commits); assertNull(slots.pairedPeer())
    }

    @Test fun the_code_clears_when_the_join_is_cancelled() = test {
        val c = coordinator(LockedStore(), deps(SyncVectors.identity("B")))
        lan.enrollHold = { Thread.sleep(60_000) }
        val join = async { c.joinByQr(SyncVectors.qrText()) }
        until("code") { c.verificationCode.value != null }
        assertNotNull(c.connecting.value)
        c.cancelJoin()
        assertFalse(join.await())
        assertEquals("Pairing was cancelled.", c.actionInfo.value)
        assertNull(c.verificationCode.value)
    }

    // MARK: M-7 (the Wi-Fi-paired peer's signing key for its folder view)

    @Test fun paired_keys_name_only_the_trusted_paired_peer() = test {
        val a = SyncVectors.identity("A")
        val gk = SyncVectors.lanGroupKey()
        val state = SyncGroupState(gk.groupId, 1, gk.key, SyncVectors.identity("B"), slots.installId(), hasFolder = true)
        assertEquals(emptyMap<String, String>(), SyncCoordinator.pairedKeys(deps(), state))
        slots.setPairedPeer(PinnedPeer(a.deviceId, gk.groupId, a.signingPublicKey, a.exchangePublicKey, LanEndpoint("192.168.1.20", 48201)))
        assertEquals(mapOf(a.deviceId to Base64Std.encode(a.signingPublicKey)), SyncCoordinator.pairedKeys(deps(), state))
        // Ruling 16: a pin of another group (or with no group state) is no key.
        assertEquals(emptyMap<String, String>(), SyncCoordinator.pairedKeys(deps(), state.copy(groupId = "other")))
        assertEquals(emptyMap<String, String>(), SyncCoordinator.pairedKeys(deps(), null))
    }

    @Test fun the_folder_run_holds_the_wifi_paired_peer_to_its_signing_key() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        assertTrue(c.actionError.value ?: "", c.joinFolder("content://picked/bm", SyncVectors.PASSWORD))
        val state = store.snapshot.sync!!
        val a = SyncVectors.identity("A")
        slots.setPairedPeer(PinnedPeer(a.deviceId, state.groupId, a.signingPublicKey, a.exchangePublicKey, LanEndpoint("192.168.1.20", 48201)))
        // A's next view, signed by C: the keyring (format 1) lists no key for A and A never signed, so only the Wi-Fi
        // pairing says it is forged (desktop `_paired_keys`, audit M-7).
        val gk = GroupKey(state.groupId, state.epoch, state.key)
        val path = "LocalGateKeys Sync/devices/${a.deviceId}.lgksync"
        val (header, states) = ViewFile.decode(folder.get(path)!!, gk, a.deviceId)
        clock.now += 60
        val next = ViewFile.encode(gk, a.deviceId, header.counter + 1, states, clock, SystemRandomSource())
        folder.put(path, next)
        folder.put(FolderLayout.signatureFile(a.deviceId)!!, ViewSignature.sign(next, ViewFile.decodeHeader(next), SyncVectors.identity("C")))
        c.sync(Trigger.MANUAL)
        assertTrue(c.issues.value.toString(), c.issues.value.any { it.kind == "view-forged" })
        assertEquals(header.counter, store.snapshot.sync!!.lastSeen[a.deviceId])
        assertNull(store.snapshot.sync!!.viewSigners[a.deviceId])
    }

    // MARK: pairing failures (Wi-Fi)

    @Test fun enroll_failures_name_the_address_and_what_to_do() = test {
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        val cases = listOf(
            LanFailure.REFUSED to "Nothing is listening at 192.168.1.20:48201. Open Sync on the PC, choose Show QR code, and scan the new code.",
            LanFailure.UNREACHABLE to "192.168.1.20:48201 cannot be reached from this phone. Check that the PC is on this Wi-Fi and that the code shows the PC's Wi-Fi address.",
            LanFailure.TIMED_OUT to "192.168.1.20:48201 did not answer. Check that Windows Firewall allows LocalGateKeys on Private networks, and that the PC is on this Wi-Fi.",
            LanFailure.CLOSED_BY_PEER to "The PC at 192.168.1.20:48201 closed the connection: the code has probably expired or is no longer waiting. Show a new code on the PC and scan it again.",
        )
        for ((kind, text) in cases) {
            lan.enrollReply = { throw LanSocketException("x", kind) }
            val joined = c.joinByQr(SyncVectors.qrText())
            assertFalse(joined)
            assertEquals("$kind", text, c.actionError.value)
            assertEquals(Phase.IDLE, c.phase.value); assertNull(c.connecting.value)
        }
        assertEquals(0, store.commits); assertNull(slots.pairedPeer())
    }

    @Test fun offer_off_this_subnet_explains_the_address_when_it_fails() = test {
        val d = deps(SyncVectors.identity("B")).copy(localSubnet = { IPv4Subnet.of("192.168.60.11", "255.255.255.0") })
        val c = coordinator(LockedStore(), d)
        val offSubnet = "The code points to 192.168.1.20 but this phone is on 192.168.60.0/24. On the PC, set the sync address to its Wi-Fi IPv4 address (ipconfig) and show a new code."
        for (kind in listOf(LanFailure.REFUSED, LanFailure.UNREACHABLE, LanFailure.TIMED_OUT, LanFailure.OTHER)) {
            lan.enrollReply = { throw LanSocketException("x", kind) }
            c.joinByQr(SyncVectors.qrText())
            assertEquals("$kind", offSubnet, c.actionError.value)
        }
        // It still dials (the address may be routed), and a close keeps its own advice.
        assertEquals(4, lan.enrolls)
        lan.enrollReply = { throw LanSocketException("x", LanFailure.CLOSED_BY_PEER) }
        c.joinByQr(SyncVectors.qrText())
        assertTrue(c.actionError.value!!.startsWith("The PC at 192.168.1.20:48201 closed the connection"))
        // On the same subnet: the plain message.
        val same = coordinator(LockedStore(), d.copy(localSubnet = { IPv4Subnet.of("192.168.1.9", "255.255.255.0") }))
        lan.enrollReply = { throw LanSocketException("x", LanFailure.REFUSED) }
        same.joinByQr(SyncVectors.qrText())
        assertEquals(
            "Nothing is listening at 192.168.1.20:48201. Open Sync on the PC, choose Show QR code, and scan the new code.",
            same.actionError.value,
        )
    }

    @Test fun connecting_shows_the_address_and_cancel_stops_the_join() = test {
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        lan.enrollHold = { Thread.sleep(60_000) }
        val qr = SyncVectors.qrText()
        val join = async { c.joinByQr(qr) }
        until("dial") { lan.enrolls == 1 }
        assertEquals(Phase.JOINING, c.phase.value)
        assertEquals(LanEndpoint("192.168.1.20", 48201), c.connecting.value)
        val started = System.nanoTime()
        c.cancelJoin()
        val joined = join.await()
        assertFalse(joined)
        assertTrue((System.nanoTime() - started) < 5_000_000_000L)
        assertEquals(Phase.IDLE, c.phase.value); assertNull(c.connecting.value)
        assertNull(c.actionError.value); assertEquals("Pairing was cancelled.", c.actionInfo.value)
        assertEquals(0, store.commits); assertNull(slots.pairedPeer())
    }

    @Test fun connecting_clears_once_connected_and_cancel_is_then_ignored() = test {
        inviterAnswers()
        val c = coordinator(LockedStore(), deps(SyncVectors.identity("B")))
        val gate = AsyncGate()
        lan.connectsBeforeHold = true
        lan.enrollHold = { gate.await() }
        val qr = SyncVectors.qrText()
        val join = async { c.joinByQr(qr) }
        until("held reply") { gate.waiting == 1 }
        until("connected hop") { c.connecting.value == null }
        assertEquals(Phase.JOINING, c.phase.value)
        c.cancelJoin() // no Cancel once connected: the reply is being processed
        gate.open()
        assertTrue(join.await())
    }

    @Test fun shutdown_and_wait_waits_for_a_join_in_flight() = test {
        val c = coordinator(LockedStore(), deps(SyncVectors.identity("B")))
        val gate = AsyncGate()
        lan.enrollHold = { gate.await() }
        val qr = SyncVectors.qrText()
        val join = async { c.joinByQr(qr) }
        until("held dial") { gate.waiting == 1 }
        var done = false
        val shut = async { c.shutdownAndWait(); done = true }
        settle(200)
        assertFalse("shutdownAndWait returned while the join was still in flight", done)
        gate.open()
        shut.await()
        join.await()
        assertTrue(done)
    }

    @Test fun join_by_folder_with_password() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)

        // A wrong password is refused with the desktop wording and changes nothing.
        val wrong = c.joinFolder("content://picked/bm", "wrong password here")
        assertFalse(wrong)
        assertEquals("That sync password is not right for this folder.", c.actionError.value)
        assertEquals(0, store.commits); assertNull(folderUri())

        val ok = c.joinFolder("content://picked/bm", SyncVectors.PASSWORD)
        assertTrue(c.actionError.value ?: "", ok)
        val state = store.snapshot.sync!!
        assertTrue(state.hasFolder)
        assertFalse(store.snapshot.records.isEmpty()) // A, B and C's items merged in the first run
        assertNotNull(folder.get("LocalGateKeys Sync/devices/${state.deviceId}.lgksync"))
        // The folder URI is kept in the sealed slots; the folder is used on the next sync.
        assertEquals("content://picked/bm", folderUri())
        assertTrue(c.membership.value.hasFolder); assertTrue(c.membership.value.hasFolderUri)
        assertEquals(1, autoFill.calls)
        assertEquals("This phone now syncs through the cloud folder.", c.actionInfo.value)
        val opens = folders.opened.size
        c.sync(Trigger.APP_OPEN)
        assertEquals(opens + 1, folders.opened.size)
        assertEquals("content://picked/bm", folders.opened.last())
        assertEquals(2, autoFill.calls)
    }

    @Test fun wrong_password_backs_off_after_five_attempts() = test {
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_epoch1.json"))
        val c = coordinator(LockedStore())
        // Argon2id runs only until the back-off: attempt 6 is refused without reading the folder.
        repeat(5) { c.joinFolder("content://f/1", "nope nope nope") }
        val opens = folders.opened.size
        c.joinFolder("content://f/1", SyncVectors.PASSWORD)
        assertEquals(SyncWording.PASSWORD_BACKOFF_TEXT, c.actionError.value)
        assertEquals(opens, folders.opened.size)
        clock.now += 30
        c.joinFolder("content://f/1", SyncVectors.PASSWORD)
        assertNull(c.actionError.value)
    }

    @Test fun attach_after_qr_keeps_the_pairing() = test {
        // QR-joined to the existing-group vector group (A created it; the phone holds the epoch-1 key).
        val x = SyncVectors.json("expected.json")
        val existing = SyncVectors.obj(x["existing_group"])
        val gid = SyncVectors.str(existing["group_id"])
        val key = SyncVectors.hex(SyncVectors.str(SyncVectors.obj(SyncVectors.obj(existing["epochs"])["1"])["group_key_hex"]))
        val me = DeviceIdentity.generate(random = SystemRandomSource())
        val install = slots.installId()
        val store = LockedStore(StoreSnapshot(sync = SyncGroupState(gid, 1, key, me, install, hasFolder = false)))
        val a = SyncVectors.identity("A")
        val peer = PinnedPeer(a.deviceId, gid, a.signingPublicKey, a.exchangePublicKey, LanEndpoint("192.168.1.20", 47821))
        slots.setPairedPeer(peer)
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_existing_epoch1.json"))
        clock.now = 1_790_000_000 + 1000

        val c = coordinator(store)
        c.refreshMembership()
        assertTrue(c.membership.value.joined); assertFalse(c.membership.value.hasFolder)
        val ok = c.joinFolder("content://f/7", SyncVectors.str(SyncVectors.obj(existing["attach"])["password"]))
        assertTrue(c.actionError.value ?: "", ok)
        val state = store.snapshot.sync!!
        assertTrue(state.hasFolder)
        assertEquals(me, state.identity) // attach: no new identity, no re-merge
        assertEquals(gid, state.groupId)
        assertTrue(state.members.contains(me.deviceId))
        assertEquals(peer, slots.pairedPeer()) // Wi-Fi pairing kept
        assertEquals(1, lan.exchanges) // and still synced after the attach
        // Its own file is in the folder now.
        assertNotNull(folder.get("LocalGateKeys Sync/devices/${me.deviceId}.lgksync"))
    }

    // MARK: running

    @Test fun issues_map_to_the_desktop_wording() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        lan.exchange = { throw LanSocketException("connect failed: refused") }
        c.sync(Trigger.MANUAL)
        assertEquals(listOf("unreachable"), c.issues.value.map { it.kind })
        assertEquals(
            "A device could not be reached on this network. Check that it is on the same Wi-Fi and that LocalGateKeys is unlocked there.",
            c.issues.value.first().text,
        )
        assertEquals(SyncWording.Severity.NOTICE, c.issues.value.first().severity)
        lan.exchange = { throw LanSyncException("epoch-behind", "a1111111-0000-4000-8000-00000000000a") }
        c.sync(Trigger.MANUAL)
        assertEquals(
            "This phone has an older sync key than Device a1111111. Leave sync on this phone, then pair it again.",
            c.issues.value.first().text,
        )
        lan.exchange = { throw LanSyncException("bad-message") }
        c.sync(Trigger.MANUAL)
        assertEquals(listOf("bad-reply"), c.issues.value.map { it.kind })
    }

    @Test fun no_concurrent_syncs() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val base = lan.exchanges
        lan.gated = true
        val first = async { c.sync(Trigger.APP_OPEN) }
        until("exchange held") { lan.waiting == 1 }
        assertEquals(Phase.SYNCING, c.phase.value)
        // Pull-to-refresh and an edit while the run is in flight: folded into ONE more run after it.
        val second = async { c.sync(Trigger.PULL_TO_REFRESH) }
        val third = async { c.sync(Trigger.LOCAL_EDIT) }
        settle()
        assertEquals(base + 1, lan.exchanges)
        val joinWhileBusy = c.joinByQr(SyncVectors.qrText())
        assertFalse(joinWhileBusy)
        assertEquals("Items changed while syncing; sync tries again shortly.", c.actionError.value)
        lan.release()
        first.await(); second.await(); third.await()
        assertEquals(base + 2, lan.exchanges)
        assertEquals(1, lan.maxConcurrent)
        assertEquals(Phase.IDLE, c.phase.value)
    }

    @Test fun edits_trigger_one_debounced_sync() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val base = lan.exchanges
        val runs = c.completedRuns.value
        c.noteLocalEdit(); c.noteLocalEdit(); c.noteLocalEdit()
        until("the debounced run") { c.completedRuns.value > runs }
        settle()
        assertEquals(base + 1, lan.exchanges)
        assertTrue(sleeper.slept.isNotEmpty())
        assertTrue(sleeper.slept.all { it == 2_000L })
        // The edited item is what the next run publishes.
        assertEquals(base + 1, lan.sent.size)
    }

    @Test fun failed_sync_leaves_store_untouched() = test {
        val store = LockedStore()
        val (id, wrapper) = noteRecord(3)
        val c = qrJoined(store)
        val snap = store.snapshot
        store.commit(StoreChange(snap.revision, snap.records + (id to wrapper), snap.meta, snap.sync))
        val before = store.snapshot
        val commits = store.commits
        val failures: List<Exception> = listOf(
            LanSyncException("bad-chunk"), LanSyncException("device-mismatch", "x"), LanSocketException("read timed out"),
            LanTransportException(LanTransportException.Kind.AUTHENTICATION, "bad hello"),
        )
        for (failure in failures) {
            lan.exchange = { throw failure }
            c.sync(Trigger.MANUAL)
            assertEquals(before, store.snapshot)
            assertEquals(commits, store.commits)
            assertFalse(c.issues.value.isEmpty())
        }
        // A folder group whose folder URI is gone: reported, store untouched.
        val s = store.snapshot
        store.commit(StoreChange(s.revision, s.records, s.meta, s.sync!!.copy(hasFolder = true)))
        val folderBefore = store.snapshot
        c.sync(Trigger.MANUAL)
        assertTrue(c.issues.value.any { it.kind == "folder-missing" })
        assertEquals(folderBefore, store.snapshot)
    }

    @Test fun lan_refuses_a_non_lan_peer_address() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val p = slots.pairedPeer()!!
        // A stored peer can only hold a validated LAN endpoint; a forged one is refused before any connect.
        slots.write(
            Slot.PAIRED_PEER,
            ("""{"device_id":"${p.deviceId}","endpoint":{"host":"8.8.8.8","port":443},"exchange_public":"${Base64Std.encode(p.exchangePublic)}",""" +
                """"group_id":"${p.groupId}","signing_public":"${Base64Std.encode(p.signingPublic)}"}""").toByteArray(),
        )
        val base = lan.exchanges
        c.sync(Trigger.MANUAL)
        assertEquals(base, lan.exchanges)
        assertFalse(c.issues.value.isEmpty())
    }

    @Test fun choose_the_folder_again_stores_the_uri_without_joining() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        assertTrue(c.joinFolder("content://f/1", SyncVectors.PASSWORD))
        val member = store.snapshot.sync!!
        slots.delete(Slot.FOLDER_URI) // e.g. the slot write after the join failed
        c.refreshMembership(); assertFalse(c.membership.value.hasFolderUri)

        // A folder holding another group is refused and the URI is not stored.
        val other = MemoryFolder()
        other.put("LocalGateKeys Sync/keyring.lgkkeys", SyncVectors.data("keyring_existing_epoch1.json"))
        val c2 = coordinator(store, deps().copy(folders = FakeFolders(other)))
        assertFalse(c2.joinFolder("content://f/9", ""))
        assertEquals(
            "That folder holds a different sync group. Choose another folder, or the folder your other device added to this group.",
            c2.actionError.value,
        )
        assertNull(folderUri())

        val ok = c.joinFolder("content://f/2", "")
        assertTrue(c.actionError.value ?: "", ok)
        assertEquals("content://f/2", folderUri())
        assertEquals(member.identity, store.snapshot.sync?.identity) // no new join
        assertTrue(c.membership.value.hasFolderUri)
    }

    @Test fun choosing_the_folder_again_is_not_subject_to_the_password_backoff() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        repeat(5) { c.joinFolder("content://f/1", "nope nope nope") }
        // The vault joins the group (another coordinator over the same store), then the folder URI is lost.
        assertTrue(coordinator(store).joinFolder("content://f/1", SyncVectors.PASSWORD))
        slots.delete(Slot.FOLDER_URI)
        // Re-picking checks no password, so the 30 s back-off does not apply.
        val ok = c.joinFolder("content://f/3", "")
        assertTrue(c.actionError.value ?: "", ok)
        assertEquals("content://f/3", folderUri())
    }

    @Test fun failed_folder_reads_never_commit() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        // A bad password: refused, nothing committed.
        assertFalse(c.joinFolder("content://f/1", "not the sync password"))
        assertEquals(0, store.commits)
        assertTrue(c.joinFolder("content://f/1", SyncVectors.PASSWORD))
        c.sync(Trigger.MANUAL); c.sync(Trigger.MANUAL) // settle
        val a = SyncVectors.identity("A").deviceId

        // A corrupt device file: reported, skipped, no commit.
        var commits = store.commits
        val goodA = folder.get("LocalGateKeys Sync/devices/$a.lgksync")!!
        folder.put("LocalGateKeys Sync/devices/$a.lgksync", goodA.copyOf(40) + ByteArray(64) { 0x41 })
        c.sync(Trigger.MANUAL)
        assertTrue(c.issues.value.any { it.kind == "corrupt" })
        assertEquals(commits, store.commits)
        folder.put("LocalGateKeys Sync/devices/$a.lgksync", goodA)

        // A tampered key file: sync stops, no commit.
        commits = store.commits
        val ring = folder.get("LocalGateKeys Sync/keyring.lgkkeys")!!.copyOf()
        val snapshot = store.snapshot
        val i = ring.indexOf('"'.code.toByte())
        ring[i + 30] = (ring[i + 30].toInt() xor 0x01).toByte()
        folder.put("LocalGateKeys Sync/keyring.lgkkeys", ring)
        c.sync(Trigger.MANUAL)
        // Tampered or damaged: either sync stops, or the trusted copy is put back; the store is untouched.
        assertTrue(
            "${c.issues.value.map { it.kind }}",
            c.issues.value.any { it.kind in setOf("tampered", "keyring-corrupt", "keyring-restored") },
        )
        assertEquals(commits, store.commits)
        assertEquals(snapshot, store.snapshot)
    }

    @Test fun edit_during_a_failed_join_syncs_afterwards() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val base = lan.exchanges
        lan.enrollReply = { throw LanSocketException("x") }
        // Hold the join (already joined, so it fails at once) while an edit sync asks to run.
        val join = async { c.joinByQr("lgk-pair:x") }
        c.sync(Trigger.LOCAL_EDIT) // may run before or during the join; either way it must not be lost
        join.await()
        until("the edit's sync") { lan.exchanges >= base + 1 }
    }

    @Test fun nothing_commits_after_lock() = test {
        val store = LockedStore()
        val (id, wrapper) = noteRecord(9)
        val c = qrJoined(store)
        val a = SyncVectors.identity("A")
        lan.exchange = { peerStates(mapOf(id to wrapper), a.deviceId, 1_790_000_030) }
        lan.gated = true
        val run = async { c.sync(Trigger.MANUAL) }
        until("exchange held") { lan.waiting == 1 }
        val commits = store.commits
        c.shutdown() // the vault locks mid-run
        c.noteLocalEdit()
        lan.release()
        run.await()
        assertEquals(commits, store.commits)
        assertNull(store.snapshot.records[id])
        c.sync(Trigger.MANUAL)
        assertEquals(commits, store.commits)
    }

    @Test fun lock_mid_run_stops_reads_identity_refresh_and_commits() = test {
        val store = LockedStore()
        val (id, wrapper) = noteRecord(9)
        val c = qrJoined(store)
        val a = SyncVectors.identity("A")
        lan.exchange = { peerStates(mapOf(id to wrapper), a.deviceId, 1_790_000_030) }
        lan.gated = true
        val run = async { c.sync(Trigger.MANUAL) }
        until("exchange held") { lan.waiting == 1 }
        val loads = store.loads
        val commits = store.commits
        val refreshes = autoFill.calls
        c.shutdown() // the vault locks while the exchange is in flight
        lan.release()
        run.await()
        settle()
        assertEquals("no store read after lock", loads, store.loads)
        assertEquals("no identity refresh after lock", refreshes, autoFill.calls)
        assertEquals("no commit after lock", commits, store.commits)
        try {
            c.store.load()
            fail("the gated store refuses reads after lock")
        } catch (e: SyncActionException) {
            assertEquals("locked", e.reason)
        }
        assertEquals(loads, store.loads)
    }

    /**
     * Android extra (Review Focus 1): the phone locks while a folder run is half way through its reads. The run
     * stops without writing: no store commit, no own file in the folder, no slot written; counters never roll back.
     */
    @Test fun lock_during_sync_writes_nothing() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        assertTrue(c.joinFolder("content://f/1", SyncVectors.PASSWORD))
        // A local edit, so the next run would commit its sync meta and rewrite this phone's file.
        val (id, wrapper) = noteRecord(5, title = "Late")
        val edited = store.snapshot
        store.commit(StoreChange(edited.revision, edited.records + (id to wrapper), edited.meta, edited.sync))
        val counters = VaultCounterStore(slots)
        counters.persistHelloCounter(41)
        counters.setLastAcceptedCounter(7, "peer")
        val commits = store.commits
        val before = store.snapshot
        val folderBefore = folder.snapshot()
        val slotsBefore = Slot.entries.associateWith { slots.read(it)?.toList() }
        val reached = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        folder.onRead = { path ->
            if (path.endsWith(".lgksync") && reached.count > 0L) {
                reached.countDown()
                resume.await()
            }
        }
        val run = async { c.sync(Trigger.MANUAL) }
        until("folder read in flight") { reached.count == 0L }
        // What AppLockModel.lock does: the coordinator's gate, then the vault's write gates (Ruling 11).
        c.shutdown()
        slots.beginClose()
        resume.countDown()
        run.await()
        settle()
        assertEquals("no commit after lock", commits, store.commits)
        assertEquals(before, store.snapshot)
        assertNull("the edit got no sync meta", store.snapshot.meta[id])
        assertEquals("nothing written to the folder", folderBefore, folder.snapshot())
        assertEquals(Phase.IDLE, c.phase.value)
        // A fresh slots view of the same file: nothing changed, the hello counter did not roll back.
        val reopened = SecretSlots(java.io.File(tmp.root, "secrets.bin"), ByteArray(32) { 3 }, SystemRandomSource())
        assertEquals(slotsBefore, Slot.entries.associateWith { reopened.read(it)?.toList() })
        assertEquals(41L, VaultCounterStore(reopened).persistedHelloCounter())
        assertEquals(7L, VaultCounterStore(reopened).lastAcceptedCounter("peer"))
    }

    @Test fun leave_and_reset() = test {
        val store = LockedStore()
        val (id, wrapper) = noteRecord(4)
        lan.exchange = { emptyList() }
        val c = qrJoined(store)
        val snap = store.snapshot
        store.commit(StoreChange(snap.revision, snap.records + (id to wrapper), snap.meta, snap.sync))
        c.sync(Trigger.MANUAL) // gives the item sync meta
        assertFalse(store.snapshot.meta.isEmpty())
        slots.write(Slot.FOLDER_URI, "content://f/1".toByteArray())

        c.leave()
        assertNull(store.snapshot.sync); assertEquals(wrapper, store.snapshot.records[id])
        assertFalse(store.snapshot.meta.isEmpty()) // leave keeps the sync history
        assertNull(slots.pairedPeer()); assertNull(folderUri())
        assertEquals("This phone left sync. Remove it on one of your other devices.", c.actionInfo.value)
        assertFalse(c.membership.value.joined)

        c.reset()
        assertTrue(store.snapshot.meta.isEmpty()); assertEquals(wrapper, store.snapshot.records[id])
        assertEquals("Sync was reset on this phone.", c.actionInfo.value)
        c.reset()
        assertEquals("There was nothing to reset.", c.actionInfo.value)
        assertEquals("Are you sure? This cannot be undone. Reset sync on this phone now?", SyncWording.onPhone(SyncWording.RESET_TEXT_2))
    }

    /** Map rule: the hello counter is this device's own monotonic counter (kept); peer counters go with the pairing. */
    @Test fun leave_and_reset_keep_the_hello_counter_and_drop_peer_counters() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val counters = VaultCounterStore(slots)
        counters.persistHelloCounter(1234)
        counters.setLastAcceptedCounter(99, "a1111111-0000-4000-8000-00000000000a")
        c.leave()
        assertEquals(1234L, counters.persistedHelloCounter())
        assertNull(slots.read(Slot.PEER_COUNTERS))
        assertEquals(0L, counters.lastAcceptedCounter("a1111111-0000-4000-8000-00000000000a"))
        counters.setLastAcceptedCounter(5, "x")
        c.reset()
        assertEquals(1234L, counters.persistedHelloCounter())
        assertNull(slots.read(Slot.PEER_COUNTERS))
        assertNotNull(slots.read(Slot.INSTALL_ID))
    }

    @Test fun failures_never_escape_to_the_caller() = test {
        // A store that cannot be read: sync reports local-data, actions report through actionError.
        val broken = object : ItemStore {
            override fun load(): StoreSnapshot = throw IllegalStateException("disk gone")
            override fun commit(change: StoreChange) = throw IllegalStateException("disk gone")
        }
        val c = coordinator(broken)
        c.sync(Trigger.PULL_TO_REFRESH)
        assertEquals(listOf("local-data"), c.issues.value.map { it.kind })
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertEquals(SyncWording.STEP_FAILED_COPY, c.actionError.value)
        c.leave()
        assertEquals(SyncWording.STEP_FAILED_COPY, c.actionError.value)
        assertEquals(Phase.IDLE, c.phase.value)
    }

    @Test fun to_string_shows_no_secrets() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val key = store.snapshot.sync!!.key
        val hexKey = key.joinToString("") { "%02x".format(it) }
        val b64Key = Base64Std.encode(key)
        val texts = listOf(c.toString(), c.deps.toString(), c.store.toString(), c.membership.value.toString(), c.gate.toString())
        for (t in texts) {
            assertFalse(t, t.contains(hexKey)); assertFalse(t, t.contains(b64Key))
            assertFalse(t, t.contains("[B@")) // no raw byte arrays
        }
        val e = EnrollConnectException(LanFailure.REFUSED, LanEndpoint("192.168.1.20", 1), null)
        assertEquals("EnrollConnectException(failure=REFUSED, endpoint=192.168.1.20:1, offSubnet=null)", e.toString())
        assertSame(store, (c.store as GatedStore).base)
    }

    // MARK: fix round 1

    /** Review 1: the caller stops waiting mid-join; the join still finishes with all its bookkeeping, and blocks other actions. */
    @Test fun caller_cancelled_mid_join_still_finishes_the_join() = test {
        inviterAnswers()
        lan.exchange = { emptyList() }
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        val gate = AsyncGate()
        lan.enrollHold = { gate.await() }
        val qr = SyncVectors.qrText()
        val caller = launch { c.joinByQr(qr) }
        until("held dial") { gate.waiting == 1 }
        try {
            caller.cancel(); caller.join()
            assertEquals("the join keeps running", Phase.JOINING, c.phase.value)
            c.leave()
            assertEquals("Items changed while syncing; sync tries again shortly.", c.actionError.value)
            assertFalse(c.joinFolder("content://f/1", "pw"))
            assertFalse(c.joinByQr(qr))
            assertEquals(1, lan.enrolls)
        } finally {
            gate.open() // a failure never leaves the dial blocked
        }
        until("join and first sync") { c.completedRuns.value >= 1 && c.phase.value == Phase.IDLE }
        assertNotNull(store.snapshot.sync)
        assertTrue(c.membership.value.joined)
        assertEquals(slots.pairedPeer(), c.membership.value.peer)
        assertEquals("This phone joined the sync group. The first sync is running.", c.actionInfo.value)
        assertEquals("the first sync ran", 1, lan.exchanges)
        // Free again.
        c.leave()
        assertEquals("This phone left sync. Remove it on one of your other devices.", c.actionInfo.value)
    }

    /** Review 1: the same for leave/reset and folder joins: a cancelled caller never skips the bookkeeping. */
    @Test fun caller_cancelled_mid_folder_join_still_reports() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        val reached = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        folder.onRead = { if (reached.count > 0L) { reached.countDown(); resume.await() } }
        val caller = launch { c.joinFolder("content://f/1", SyncVectors.PASSWORD) }
        until("folder read") { reached.count == 0L }
        try {
            caller.cancel(); caller.join()
            assertEquals(Phase.JOINING, c.phase.value)
        } finally {
            resume.countDown()
        }
        until("join finished") { c.actionInfo.value != null || c.actionError.value != null }
        assertEquals("This phone now syncs through the cloud folder.", c.actionInfo.value)
        assertTrue(c.membership.value.hasFolder)
        assertEquals("content://f/1", folderUri())
    }

    /** Ruling 16 (a): a lock before the pin pins nothing. */
    @Test fun lock_before_the_pin_pins_nothing() = test {
        inviterAnswers()
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        slots.installId() // exists already, so the join reads it and writes nothing else before the pin
        c.refreshMembership()
        // The spy: every slot write (the pin, or a pin and its rollback) replaces secrets.bin with new bytes (fresh nonce).
        val file = java.io.File(tmp.root, "secrets.bin")
        val before = file.readBytes()
        val answer = lan.enrollReply
        lan.enrollReply = { r -> answer(r).also { c.gate.close() } }
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        assertTrue("no slot write at all: the pin was never attempted", before.contentEquals(file.readBytes()))
        assertNull(slots.pairedPeer())
        assertEquals(0, store.commits)
    }

    /**
     * Review round 2, 1: a membership refresh that loaded "not joined" just before a QR join finishes after the join has
     * pinned and committed. Its cleanup re-reads the state under the pin lock, so the fresh pin survives, and its late
     * result never replaces the newer membership.
     */
    @Test fun a_late_refresh_never_drops_a_fresh_pin() = test {
        inviterAnswers()
        lan.exchange = { emptyList() }
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        c.refreshMembership()
        val held = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        var armed = true
        store.onLoad = {
            if (armed && Thread.currentThread().stackTrace.any { "${it.className}.${it.methodName}".contains("refreshMembership") }) {
                armed = false
                held.countDown()
                release.await()
            }
        }
        val late = async { c.refreshMembership() }
        until("refresh holding its load") { held.count == 0L }
        try {
            assertTrue(c.actionError.value ?: "", c.joinByQr(SyncVectors.qrText()))
        } finally {
            release.countDown()
        }
        late.await()
        store.onLoad = null
        val peer = slots.pairedPeer()
        assertNotNull("the fresh pin survives", peer)
        assertTrue(c.membership.value.joined)
        assertEquals(peer, c.membership.value.peer)
    }

    /** Review round 2, 2: after a folder join committed, an unreadable store only skips the LAN step; success is reported. */
    @Test fun a_read_failure_after_the_folder_join_still_reports_success() = test {
        seedEpoch1Folder()
        val store = LockedStore()
        val c = coordinator(store)
        c.refreshMembership()
        var thrown = false
        store.onLoad = {
            val stack = Thread.currentThread().stackTrace
            if (!thrown && store.commits > 0 && stack.any { "${it.className}.${it.methodName}".contains("joinFolderWork") } &&
                stack.none { it.className.contains("FolderSync") }
            ) {
                thrown = true
                throw IllegalStateException("disk hiccup")
            }
        }
        val runs = c.completedRuns.value
        assertTrue(c.actionError.value ?: "", c.joinFolder("content://f/1", SyncVectors.PASSWORD))
        store.onLoad = null
        assertTrue("the post-join read failed once", thrown)
        assertEquals("This phone now syncs through the cloud folder.", c.actionInfo.value)
        assertNull(c.actionError.value)
        assertTrue("the list reloads", c.completedRuns.value > runs)
        assertTrue(store.snapshot.sync!!.hasFolder)
    }

    /**
     * Ruling 16 (b): the lock lands between the pin and the commit and the cleanup cannot delete the pin (slots shut).
     * After the next unlock the leftover peer is not trusted, is removed, and a new QR join works without peer-mismatch.
     */
    @Test fun lock_between_pin_and_commit_leaves_no_trusted_peer() = test {
        inviterAnswers()
        lan.exchange = { emptyList() }
        val store = LockedStore()
        val c = coordinator(store, deps(SyncVectors.identity("B")))
        c.refreshMembership()
        val first = slots
        var armed = true
        store.onLoad = {
            if (armed && first.read(Slot.PAIRED_PEER) != null) {
                armed = false
                c.gate.close() // the lock: coordinator gate, then the vault's slots
                first.beginClose()
            }
        }
        assertFalse(c.joinByQr(SyncVectors.qrText()))
        store.onLoad = null
        assertNull(store.snapshot.sync)
        assertEquals(0, store.commits)
        // Re-unlock: new slots over the same file still hold the leftover pin.
        slots = SecretSlots(java.io.File(tmp.root, "secrets.bin"), ByteArray(32) { 3 }, SystemRandomSource())
        assertNotNull("the leftover pin is on disk", slots.pairedPeer())
        val again = coordinator(store, deps(SyncVectors.identity("B")))
        again.refreshMembership()
        assertFalse(again.membership.value.joined)
        assertNull(again.membership.value.peer)
        assertNull("removed at the next opportunity", slots.pairedPeer())
        assertTrue(again.actionError.value ?: "", again.joinByQr(SyncVectors.qrText()))
        assertTrue(again.membership.value.joined)
        assertTrue(again.issues.value.none { it.kind == "peer-mismatch" })
        assertEquals(1, lan.exchanges)
    }

    @Test fun a_peer_of_another_group_is_never_used() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val p = slots.pairedPeer()!!
        slots.setPairedPeer(PinnedPeer(p.deviceId, "other-group", p.signingPublic, p.exchangePublic, p.endpoint))
        val base = lan.exchanges
        c.sync(Trigger.MANUAL)
        assertEquals("no exchange with a peer of another group", base, lan.exchanges)
        assertNull(c.membership.value.peer)
        assertTrue(c.issues.value.none { it.kind == "peer-mismatch" })
    }

    /** Review minor 3: the same lock over a real LocalStore: its own write gate (Ruling 11) refuses the run's commit. */
    @Test fun lock_during_sync_writes_nothing_over_a_local_store() = test {
        seedEpoch1Folder()
        val dir = tmp.newFolder("Vault")
        val key = ByteArray(32) { 11 }
        val local = app.localgatekeys.android.vault.LocalStore.open(dir, key, SystemRandomSource(), null)
        val c = coordinator(local)
        assertTrue(c.actionError.value ?: "", c.joinFolder("content://f/1", SyncVectors.PASSWORD))
        val (id, wrapper) = noteRecord(6, title = "Edit")
        val edited = local.load()
        local.commit(StoreChange(edited.revision, edited.records + (id to wrapper), edited.meta, edited.sync))
        val revision = app.localgatekeys.android.vault.LocalStore.committedRevision(dir)
        val folderBefore = folder.snapshot()
        val reached = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        folder.onRead = { path ->
            if (path.endsWith(".lgksync") && reached.count > 0L) { reached.countDown(); resume.await() }
        }
        val run = async { c.sync(Trigger.MANUAL) }
        until("folder read in flight") { reached.count == 0L }
        // Only the vault's own gates close here (UnlockedVault.beginClose): the store refuses the commit by itself.
        local.beginClose()
        slots.beginClose()
        resume.countDown()
        run.await()
        assertEquals("no commit after lock", revision, app.localgatekeys.android.vault.LocalStore.committedRevision(dir))
        assertEquals("nothing written to the folder", folderBefore, folder.snapshot())
        assertEquals(Phase.IDLE, c.phase.value)
        c.shutdown()
        local.close()
        val reopened = app.localgatekeys.android.vault.LocalStore.open(dir, key, SystemRandomSource(), null)
        assertNull("the edit got no sync meta", reopened.load().meta[id])
        reopened.close()
    }

    /** Review minor 4: calls from other threads hop to the coordinator's thread: still one run at a time, one folded re-run. */
    @Test fun calls_from_any_thread_are_confined() = test {
        val store = LockedStore()
        val c = qrJoined(store)
        val base = lan.exchanges
        lan.gated = true
        val first = async(Dispatchers.Default) { c.sync(Trigger.MANUAL) }
        until("exchange held") { lan.waiting == 1 }
        val more = (1..8).map { async(Dispatchers.Default) { c.sync(Trigger.PULL_TO_REFRESH) } }
        val busyJoin = async(Dispatchers.Default) { c.joinByQr(SyncVectors.qrText()) }
        settle()
        lan.release()
        first.await(); more.awaitAll()
        assertFalse(busyJoin.await())
        assertEquals(1, lan.maxConcurrent)
        assertEquals(base + 2, lan.exchanges)
        assertEquals(Phase.IDLE, c.phase.value)
    }
}
