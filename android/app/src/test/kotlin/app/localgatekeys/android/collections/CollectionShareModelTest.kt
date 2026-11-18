package app.localgatekeys.android.collections

import app.localgatekeys.android.i18n.EnglishTxt
import app.localgatekeys.android.sync.FakeFolders
import app.localgatekeys.android.sync.MemoryFolder
import app.localgatekeys.android.sync.ShareDevice
import app.localgatekeys.android.sync.SharePasswords
import app.localgatekeys.android.sync.ShareRuns
import app.localgatekeys.android.sync.SyncCoordinator
import app.localgatekeys.android.sync.SyncVectors
import app.localgatekeys.android.sync.SyncWording
import app.localgatekeys.android.unlock.TestClock
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.sync.CollectionCatalog
import app.localgatekeys.core.sync.CollectionShares
import app.localgatekeys.core.sync.CollectionStates
import app.localgatekeys.core.sync.FolderLayout
import app.localgatekeys.core.sync.ShareGroups
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.SyncIssue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Sub-plan 07 Task 5m: the phone's Share and Join sheet model ([CollectionShareModel]), ports of the iPhone's
 * `CollectionShareModelTests` (themselves ports of the desktop `CollectionShare.test.js`), over two [ShareDevice]s sharing
 * one memory folder. Real share key derivation through the coordinator.
 */
class CollectionShareModelTest {
    @get:Rule val tmp = TemporaryFolder()

    private val t = EnglishTxt()
    private lateinit var clock: TestClock
    private lateinit var folder: MemoryFolder
    private val scopes = ArrayList<CoroutineScope>()
    private val devices = ArrayList<ShareDevice>()

    /** The stubbed device-owner check (fingerprint, face or screen lock): its answer and how often it was asked. */
    private var ownerConfirms = true
    private var ownerAsks = 0

    @Before fun setUp() {
        clock = TestClock(SyncVectors.lanNow())
        folder = MemoryFolder()
    }

    @After fun tearDown() {
        devices.forEach { it.coordinator.shutdown() }
        scopes.forEach { it.cancel() }
    }

    private fun test(body: suspend CoroutineScope.() -> Unit) = runBlocking { withTimeout(120_000) { body() } }

    private fun CoroutineScope.device(): ShareDevice {
        val scope = CoroutineScope(coroutineContext.minusKey(Job) + SupervisorJob())
        scopes.add(scope)
        return ShareDevice(folder, clock, tmp.newFile(), scope, FakeFolders(folder)).also { devices.add(it) }
    }

    private fun model(d: ShareDevice, cid: String?): CollectionShareModel =
        CollectionShareModel(cid, d.coordinator, t, folderName = { "Family folder" }, confirmOwner = {
            ownerAsks += 1
            ownerConfirms
        }).also { it.reload() } // the sheet does this when it appears

    /** A "Family" collection in [d]'s vault. */
    private fun family(d: ShareDevice): String {
        val (change, id) = CollectionCatalog.create("Family", snapshot = d.store.snapshot, now = clock.now)
        d.store.commit(change)
        return id
    }

    private class Shared(val owner: ShareDevice, val member: ShareDevice, val cid: String, val owned: CollectionShareModel)

    /** The owner shares Family read-only as "Anna"; the member joins as "Ben" and the owner's run adopts the join. */
    private suspend fun CoroutineScope.sharedFamily(): Shared {
        val owner = device()
        val member = device()
        val cid = family(owner)
        val owned = model(owner, cid)
        owned.pick("content://share/1", "Family folder")
        owned.name = "Anna"
        owned.password = SharePasswords.FIRST
        owned.passwordAgain = SharePasswords.FIRST
        assertTrue(owned.error ?: "", owned.share())
        clock.now += 1
        val joining = model(member, null)
        joining.pick("content://share/2", "Family folder")
        joining.name = "Ben"
        joining.password = SharePasswords.FIRST
        assertTrue(joining.error ?: "", joining.join())
        clock.now += 1
        owner.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        owned.reload()
        return Shared(owner, member, cid, owned)
    }

    // ---- share a collection ----

    @Test fun shares_through_a_chosen_folder_with_the_password_typed_twice_and_the_edit_choice() = test {
        val owner = device()
        val cid = family(owner)
        val m = model(owner, cid)
        val before = m.summary!!
        assertFalse(before.shared)
        assertNull(before.status)
        assertEquals(
            "This choice is fixed once the collection is shared. To change it, stop sharing and share the collection again.",
            t.s(app.localgatekeys.android.R.string.collection_share_mode_fixed),
        )

        // No folder yet: refused, nothing shared, and the passwords are gone anyway.
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        assertFalse(m.share())
        assertEquals("Choose the shared folder first.", m.error)
        assertEquals("", m.password); assertEquals("", m.passwordAgain)

        m.pick("content://share/1", "Family folder")
        m.name = "Anna"
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        m.membersCanEdit = true
        assertTrue(m.error ?: "", m.share())
        assertEquals("", m.password); assertEquals("", m.passwordAgain)
        assertNull(m.picked)
        val s = m.summary!!
        assertTrue(s.shared); assertTrue(s.isOwner)
        assertEquals("edit", s.mode)
        assertEquals("Members can edit", s.modeText)
        assertEquals("Family folder", s.folder)
        assertEquals(listOf("Anna"), s.members.map { it.name })
        assertEquals(CollectionShareModel.MemberState.OWNER, s.members.first().state)
        assertEquals("Shared it", s.members.first().stateText)
        assertTrue(s.members.first().isSelf)
        assertFalse(s.members.first().removable)
        assertEquals("“Family” is shared. Tell the others the share password and where the folder is.", m.message)
        assertNotNull(folder.get(FolderLayout.KEYRING_PATH))
        // Neither the summary, the fields nor the model's description holds the password.
        assertFalse(s.toString().contains(SharePasswords.FIRST))
        assertFalse(m.fields.value.toString().contains("Anna"))
        assertFalse(m.toString().contains(SharePasswords.FIRST))
    }

    @Test fun clears_the_password_after_a_refusal_too_and_the_free_plan_gets_the_upgrade_sheet() = test {
        val owner = device()
        val cid = family(owner)
        val m = model(owner, cid)
        m.pick("content://share/1", "Family folder")

        // A weak password or a mismatch is refused before anything runs.
        m.password = "short"; m.passwordAgain = "short"
        assertFalse(m.share())
        assertEquals(CollectionShareModel.passwordProblem("short", "short", t), m.error)
        assertEquals("", m.password)
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.SECOND
        assertFalse(m.share())
        assertEquals("The two passwords do not match.", m.error)
        assertEquals("", m.passwordAgain)

        owner.pro = false
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        assertFalse(m.share())
        assertTrue(m.state.value.showUpgrade)
        assertEquals("", m.password); assertEquals("", m.passwordAgain)
        assertEquals(0, owner.shares.size)
        assertNull(folder.get(FolderLayout.KEYRING_PATH))
        m.reload()
        assertEquals(false, m.summary?.isPro)
    }

    @Test fun sharing_asks_the_device_owner_first_and_a_refusal_shares_nothing() = test {
        val owner = device()
        val cid = family(owner)
        val m = model(owner, cid)
        m.pick("content://share/1", "Family folder")
        // Local refusals come before the owner check: a weak password never asks.
        m.password = "short"; m.passwordAgain = "short"
        m.share()
        assertEquals(0, ownerAsks)

        ownerConfirms = false
        val commits = owner.store.commits
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        assertFalse(m.share())
        assertEquals(1, ownerAsks)
        assertEquals("The fingerprint, face or screen lock check did not succeed; nothing was shared.", m.error)
        assertEquals("", m.password); assertEquals("", m.passwordAgain)
        assertEquals(0, owner.shares.size)
        assertNull(owner.store.snapshot.shares)
        assertEquals(commits, owner.store.commits)
        assertNull(folder.get(FolderLayout.KEYRING_PATH))
        assertEquals(false, m.summary?.shared)
        assertNotNull("the folder stays picked for another try", m.picked)

        ownerConfirms = true
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        assertTrue(m.error ?: "", m.share())
        assertEquals(2, ownerAsks)
        assertEquals(1, owner.shares.size)
    }

    @Test fun join_approve_remove_and_leave_never_ask_the_device_owner() = test {
        val s = sharedFamily()
        assertEquals("only the share itself asked", 1, ownerAsks)
        s.owned.selectedPending = s.owned.summary!!.pending.map { it.id }.toSet()
        s.owned.approve()
        model(s.member, s.cid).leave()
        assertEquals(1, ownerAsks)
    }

    @Test fun a_folder_that_already_holds_a_share_is_refused_with_its_words() = test {
        val s = sharedFamily()
        val (change, otherId) = CollectionCatalog.create("Work", snapshot = s.owner.store.snapshot, now = clock.now)
        s.owner.store.commit(change)
        val m = model(s.owner, otherId)
        m.pick("content://share/1", "Family folder")
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        assertFalse(m.share())
        assertEquals(CollectionShareModel.reasonText("folder-in-use", t), m.error)
        assertEquals("That folder already holds a sync group or another shared collection. Choose an empty folder.", m.error)
        assertEquals("", m.password)
        assertEquals(false, m.summary?.shared)
    }

    // ---- members ----

    @Test fun shows_who_shared_it_who_waits_and_who_was_removed_and_fixes_the_mode() = test {
        val sf = sharedFamily()
        val s = sf.owned.summary!!
        assertEquals("read", s.mode)
        assertEquals("Members can only view", s.modeText)
        assertEquals(listOf("Anna", "Ben"), s.members.map { it.name })
        assertEquals(listOf(CollectionShareModel.MemberState.OWNER, CollectionShareModel.MemberState.PENDING), s.members.map { it.state })
        assertEquals(listOf("Shared it", "Waiting for approval"), s.members.map { it.stateText })
        assertEquals(listOf(false, true), s.members.map { it.removable })
        assertEquals(listOf("Ben"), s.pending.map { it.name })
        assertEquals(emptyList<CollectionShareModel.Removed>(), s.removed)

        // The member sees itself waiting, no Remove, nothing to approve and no removed names.
        val ms = model(sf.member, sf.cid).summary!!
        assertTrue(ms.shared); assertFalse(ms.isOwner)
        assertEquals("Ben", ms.members.first { it.isSelf }.name)
        assertEquals(CollectionShareModel.MemberState.PENDING, ms.members.first { it.isSelf }.state)
        assertTrue(ms.members.none { it.removable })
        assertEquals(emptyList<CollectionShareModel.Member>(), ms.pending)
    }

    @Test fun lets_in_only_the_waiting_people_the_owner_ticks_by_name() = test {
        val sf = sharedFamily()
        val owned = sf.owned
        val ben = owned.summary!!.pending.first()
        // Nobody ticked: no confirmation, nothing approved.
        assertNull(owned.approvalNames)
        assertFalse(owned.approve())
        owned.selectedPending = setOf(ben.id, "not-a-waiting-id")
        assertEquals("Ben", owned.approvalNames)
        assertEquals(
            "Let these people into “Family”: Ben? Their devices then sync every item in this collection, and their edits count. Only approve names you recognise.",
            t.s(app.localgatekeys.android.R.string.collection_share_approve_text, "Family", "Ben"),
        )
        assertTrue(owned.error ?: "", owned.approve())
        assertEquals("Let in: Ben.", owned.message)
        assertEquals(emptyList<CollectionShareModel.Member>(), owned.summary?.pending)
        assertEquals(listOf(CollectionShareModel.MemberState.OWNER, CollectionShareModel.MemberState.MEMBER), owned.summary?.members?.map { it.state })
        assertEquals(emptySet<String>(), owned.selectedPending)
        assertEquals(emptyList<ShareGroups.Member>(), ShareGroups.pendingMembers(sf.owner.store.snapshot, owned.summary!!.groupId!!))
    }

    @Test fun removes_someone_with_a_new_share_password_and_the_removed_device_says_so() = test {
        val sf = sharedFamily()
        val owned = sf.owned
        owned.selectedPending = owned.summary!!.pending.map { it.id }.toSet()
        owned.approve()
        clock.now += 1
        sf.member.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        val ben = owned.summary!!.members.first { it.name == "Ben" }
        assertEquals(
            "Ben knows the current share password, so removing them needs a new one. The others keep syncing without typing it; give it only to people you invite later.",
            t.s(app.localgatekeys.android.R.string.collection_share_remove_hint, "Ben"),
        )

        // The owner cannot remove itself; a mismatch is refused; both clear the fields.
        val anna = owned.summary!!.members.first { it.isSelf }
        owned.newPassword = SharePasswords.SECOND; owned.newPasswordAgain = SharePasswords.SECOND
        assertFalse(owned.remove(anna.id))
        assertEquals("That person is no longer in this shared collection.", owned.error)
        owned.newPassword = SharePasswords.SECOND; owned.newPasswordAgain = "a different long phrase 77!"
        assertFalse(owned.remove(ben.id))
        assertEquals("", owned.newPassword); assertEquals("", owned.newPasswordAgain)

        clock.now += 1
        owned.newPassword = SharePasswords.SECOND; owned.newPasswordAgain = SharePasswords.SECOND
        assertTrue(owned.error ?: "", owned.remove(ben.id))
        assertEquals("", owned.newPassword); assertEquals("", owned.newPasswordAgain)
        assertEquals("Ben was removed.", owned.message)
        assertEquals(listOf("Anna"), owned.summary?.members?.map { it.name })
        assertEquals(listOf("Ben"), owned.summary?.removed?.map { it.name })

        // The removed member: the collection stays, no longer shared, and says where its items went.
        clock.now += 1
        sf.member.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        val s = model(sf.member, sf.cid).summary!!
        assertFalse(s.shared)
        assertEquals("You were removed from this shared collection. Its items on this phone were moved to the trash.", s.status?.text)
        assertNotNull(sf.member.coordinator.removedShares.value[sf.cid])
        assertEquals("Removed, items moved to the trash", t.s(app.localgatekeys.android.R.string.collection_share_removed_badge))
    }

    // ---- share v1 to share v2 ----

    @Test fun a_new_share_is_v2_and_offers_no_upgrade() = test {
        val sf = sharedFamily()
        assertFalse(sf.owned.summary!!.canUpgrade)
        assertFalse(ShareGroups.needsUpgrade(sf.owner.store.snapshot, sf.owned.summary!!.groupId!!))
        sf.owned.password = SharePasswords.FIRST; sf.owned.passwordAgain = SharePasswords.FIRST
        assertFalse(sf.owned.upgrade())
        assertEquals("This shared collection is already upgraded.", sf.owned.error)
        assertEquals("", sf.owned.password); assertEquals("", sf.owned.passwordAgain)
    }

    @Test fun the_owner_of_a_v1_share_upgrades_it_with_the_password_typed_twice() = test {
        val owner = device()
        val member = device()
        val cid = family(owner)
        // A share v1 made by an older app (the app itself only makes share v2).
        val group = ShareRuns.create(
            owner.store, owner.deps, true, cid, "content://share/1", SharePasswords.FIRST, "Anna", "read",
            shareFormat = ShareKeyring.LEGACY_SHARE_FORMAT,
        )
        val owned = model(owner, cid)
        assertTrue(owned.summary!!.canUpgrade)
        clock.now += 1
        val joining = model(member, null)
        joining.pick("content://share/2", "Family folder")
        joining.name = "Ben"
        joining.password = SharePasswords.FIRST
        assertTrue(joining.error ?: "", joining.join())
        clock.now += 1
        owner.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        owned.reload()
        owned.selectedPending = owned.summary!!.pending.map { it.id }.toSet()
        assertTrue(owned.error ?: "", owned.approve())
        clock.now += 1
        member.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        val membersModel = model(member, cid)
        assertFalse(membersModel.summary!!.canUpgrade) // only the owner upgrades

        // Typed differently: refused, still share v1, and the fields are emptied.
        owned.password = SharePasswords.FIRST; owned.passwordAgain = SharePasswords.SECOND
        assertFalse(owned.upgrade())
        assertNotNull(owned.error)
        assertEquals("", owned.password); assertEquals("", owned.passwordAgain)
        assertTrue(ShareGroups.needsUpgrade(owner.store.snapshot, group.groupId))

        // The current share password may be kept.
        clock.now += 1
        owned.password = SharePasswords.FIRST; owned.passwordAgain = SharePasswords.FIRST
        assertTrue(owned.error ?: "", owned.upgrade())
        assertEquals("Share upgraded. Only the people you let in can open its items.", owned.message)
        assertEquals("", owned.password); assertEquals("", owned.passwordAgain)
        assertFalse(owned.summary!!.canUpgrade)
        assertFalse(ShareGroups.needsUpgrade(owner.store.snapshot, group.groupId))
        assertNotNull(ShareGroups.viewKey(owner.store.snapshot, group.groupId))

        // The approved member keeps syncing: its run opens the new content key.
        clock.now += 1
        member.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        val issues = member.coordinator.shareIssues.value[group.groupId]?.map { it.kind } ?: emptyList()
        assertFalse(issues.toString(), "tampered" in issues || "update-required" in issues || "awaiting-approval" in issues)
        assertNotNull(ShareGroups.viewKey(member.store.snapshot, group.groupId))

        // Twice: refused with its words.
        owned.password = SharePasswords.FIRST; owned.passwordAgain = SharePasswords.FIRST
        assertFalse(owned.upgrade())
        assertEquals("This shared collection is already upgraded.", owned.error)
    }

    @Test fun an_upgrade_the_folder_cannot_take_yet_says_so_and_the_next_sync_writes_it() = test {
        val owner = device()
        val cid = family(owner)
        val group = ShareRuns.create(
            owner.store, owner.deps, true, cid, "content://share/1", SharePasswords.FIRST, "Anna", "read",
            shareFormat = ShareKeyring.LEGACY_SHARE_FORMAT,
        )
        val owned = model(owner, cid)
        val before = folder.get(FolderLayout.KEYRING_PATH)!!.toList()
        // The folder refuses the keyring write (offline drive, full disk): upgraded here, the message says so.
        folder.onWrite = { path ->
            if (path == FolderLayout.KEYRING_PATH) {
                throw app.localgatekeys.core.sync.FolderAccessException(
                    app.localgatekeys.core.sync.FolderAccessException.Kind.IO, path,
                )
            }
        }
        clock.now += 1
        owned.password = SharePasswords.FIRST; owned.passwordAgain = SharePasswords.FIRST
        assertTrue(owned.error ?: "", owned.upgrade())
        assertEquals(
            "Share upgraded. Only the people you let in can open its items. " +
                "The shared folder could not be updated yet; LocalGateKeys finishes this at the next sync.",
            owned.message,
        )
        assertFalse(ShareGroups.needsUpgrade(owner.store.snapshot, group.groupId))
        assertEquals(before, folder.get(FolderLayout.KEYRING_PATH)!!.toList())

        // The folder works again: the next sync writes the upgraded keyring.
        folder.onWrite = null
        clock.now += 1
        owner.coordinator.sync(SyncCoordinator.Trigger.MANUAL)
        assertTrue(String(folder.get(FolderLayout.KEYRING_PATH)!!).contains("\"content\""))
    }

    @Test fun shows_a_merged_keyring_as_information_and_a_lost_join_with_join_again() = test {
        val owner = device()
        val cid = family(owner)
        val m = model(owner, cid)
        m.pick("content://share/1", "Family folder")
        m.password = SharePasswords.FIRST; m.passwordAgain = SharePasswords.FIRST
        m.share()
        val gid = m.summary!!.groupId!!
        val snapshot = owner.store.snapshot

        val merged = CollectionShareModel.makeSummary(
            cid, snapshot, mapOf(gid to listOf(SyncIssue("keyring-merged"))), emptyMap(), true, { null }, t,
        )!!
        assertEquals(SyncWording.Severity.NOTICE, merged.status?.severity)
        assertEquals("Someone joined while you were letting others in. They are waiting for your approval below.", merged.status?.text)
        assertEquals(false, merged.status?.joinAgain)
        assertEquals("", merged.folder)

        val lost = CollectionShareModel.makeSummary(
            cid, snapshot, mapOf(gid to listOf(SyncIssue("keyring-merged"), SyncIssue("superseded"))), emptyMap(), true, { null }, t,
        )!!
        assertEquals("a warning outranks information", SyncWording.Severity.WARNING, lost.status?.severity)
        assertEquals(true, lost.status?.joinAgain)
        assertEquals(
            "Someone else joined at the same moment, so your join did not reach the others. Join again with the share password.",
            lost.status?.text,
        )

        // Join again without the password is refused before anything runs.
        assertFalse(m.rejoin())
        assertEquals("Type the share password.", m.error)
        // With one: the coordinator's join again runs and the field is emptied whatever it answers.
        m.password = SharePasswords.FIRST
        m.rejoin()
        assertEquals("", m.password)
    }

    // ---- join a shared collection ----

    @Test fun joins_through_a_folder_and_a_password_and_then_shows_that_collection() = test {
        val owner = device()
        val cid = family(owner)
        val owned = model(owner, cid)
        owned.pick("content://share/1", "Family folder")
        owned.password = SharePasswords.FIRST; owned.passwordAgain = SharePasswords.FIRST
        owned.share()

        val member = device()
        val m = model(member, null)
        assertNull(m.summary)
        // A wrong password: refused with the share wording, nothing joined, the field emptied.
        m.pick("content://share/2", "Family folder")
        m.password = "not the share password at all 9"
        assertFalse(m.join())
        assertEquals("That share password is not right for this folder.", m.error)
        assertEquals("", m.password)
        assertNull(m.collectionId)
        assertEquals(0, member.shares.size)

        clock.now += 1
        m.password = SharePasswords.FIRST
        assertTrue(m.error ?: "", m.join())
        assertEquals("", m.password)
        assertEquals(cid, m.collectionId)
        assertEquals("You joined “Family”. Its items start to sync once the person who shared it lets you in.", m.message)
        val s = m.summary!!
        assertTrue(s.shared); assertFalse(s.isOwner)
        assertEquals(CollectionShareModel.memberName("", t), s.members.first { it.isSelf }.name)
        assertEquals(listOf(cid), CollectionCatalog.collections(member.store.snapshot).map { it.id })
    }

    @Test fun the_free_plan_cannot_join_and_gets_the_upgrade_sheet() = test {
        val member = device()
        member.pro = false
        val m = model(member, null)
        m.pick("content://share/2", "Family folder")
        m.password = SharePasswords.FIRST
        assertFalse(m.join())
        assertTrue(m.state.value.showUpgrade)
        assertEquals("", m.password)
        assertNull(member.store.snapshot.shares)
    }

    @Test fun join_without_a_folder_or_password_is_refused() = test {
        val m = model(device(), null)
        m.password = SharePasswords.FIRST
        assertFalse(m.join())
        assertEquals("Choose the shared folder first.", m.error)
        m.pick("content://share/2", "Family folder")
        assertFalse(m.join())
        assertEquals("Type the share password.", m.error)
        // An empty folder holds no share.
        m.password = SharePasswords.FIRST
        assertFalse(m.join())
        assertEquals("That folder holds no shared collection. Choose the folder the person who shared it gave you.", m.error)
    }

    // ---- leave and stop sharing ----

    @Test fun a_received_share_link_offers_forget_instead_of_share() = test {
        // Final review finding 4: another of this person's devices shared Family and was lost.
        val d = device()
        val cid = family(d)
        val s = d.store.snapshot
        val link = CollectionStates.wrapper(CollectionStates.link(cid, "read", "owner"))
        d.store.commit(StoreChange(s.revision, s.records + (CollectionStates.LINK_PREFIX + cid to link), s.meta, s.sync))
        val m = model(d, cid)
        assertEquals(false, m.summary?.shared)
        assertEquals(CollectionShares.Link("read", "owner"), m.summary?.linked)
        assertTrue(m.error ?: "", m.forgetLink())
        assertEquals("The share link of “Family” was forgotten.", m.message)
        assertNull(m.summary?.linked)
        assertNull(d.store.snapshot.records[CollectionStates.LINK_PREFIX + cid])
        // Nothing left to forget; the collection can be shared from here now.
        assertFalse(m.forgetLink())
        assertEquals(
            "Forget the share link of “Family”? Do this only if the device that shares it was lost or reset. The collection and its items stay. If that device still exists, it shares the link again at its next sync.",
            t.s(app.localgatekeys.android.R.string.collection_share_forget_link_text, "Family"),
        )
    }

    @Test fun a_collection_shared_from_two_devices_says_so() = test {
        // Re-review wave B, B1: another of this person's devices shares Family too (its link is stored here).
        val sf = sharedFamily()
        assertEquals(false, sf.owned.summary?.sharedTwice)
        val s = sf.owner.store.snapshot
        val link = CollectionStates.wrapper(CollectionStates.link(sf.cid, "edit", "owner"))
        sf.owner.store.commit(StoreChange(s.revision, s.records + (CollectionStates.LINK_PREFIX + sf.cid to link), s.meta, s.sync))
        sf.owned.reload()
        assertEquals(true, sf.owned.summary?.sharedTwice)
        assertEquals(
            "This collection is shared from two of your devices; stop sharing or leave it on one.",
            t.s(app.localgatekeys.android.R.string.collection_share_shared_twice),
        )
    }

    @Test fun the_owner_stops_sharing_and_a_member_leaves_and_the_collections_stay() = test {
        val sf = sharedFamily()
        val mine = model(sf.member, sf.cid)
        assertTrue(mine.error ?: "", mine.leave())
        assertEquals("You left “Family”.", mine.message)
        assertEquals(false, mine.summary?.shared)
        assertEquals(listOf(sf.cid), CollectionCatalog.collections(sf.member.store.snapshot).map { it.id })

        assertTrue(sf.owned.error ?: "", sf.owned.leave())
        assertEquals("“Family” is no longer shared from this phone.", sf.owned.message)
        assertEquals(false, sf.owned.summary?.shared)
        assertEquals(0, sf.owner.shares.size)
        assertEquals(listOf(sf.cid), CollectionCatalog.collections(sf.owner.store.snapshot).map { it.id })
        assertEquals(
            "Stop sharing “Family” on this phone? The collection and its items stay here. The others keep their copies, but nobody can let people in or remove them any more.",
            t.s(app.localgatekeys.android.R.string.collection_share_stop_text, "Family"),
        )
    }

    // ---- rules ----

    @Test fun member_names_and_refusal_words() {
        assertEquals(SyncWording.DEVICE_NAME, CollectionShareModel.memberName("  ", t))
        assertEquals(SyncWording.DEVICE_NAME, CollectionShareModel.memberName("‮​", t))
        assertEquals("Anna", CollectionShareModel.memberName(" Anna‮ ", t))
        assertTrue(CollectionShareModel.memberName("é".repeat(60), t).toByteArray(Charsets.UTF_8).size <= 64)
        assertEquals("Unnamed device", CollectionShareModel.displayName(null, t))
        assertEquals("Ben B", CollectionShareModel.displayName("Ben\nB", t))
        assertEquals("That share password is not right for this folder.", CollectionShareModel.reasonText("password", t))
        assertEquals("Only the device that shared this collection can do that.", CollectionShareModel.reasonText("not-owner", t))
        val words = SyncWording(t)
        assertEquals(words.shareCopy(SyncIssue("pro-required")), CollectionShareModel.reasonText("pro-required", t))
        assertEquals(words.errorText("busy"), CollectionShareModel.reasonText("busy", t))
        assertEquals("This shared collection is already upgraded.", CollectionShareModel.reasonText("already-upgraded", t))
        val update = "This shared collection needs a newer version of LocalGateKeys. Update the app to keep syncing it."
        assertEquals(update, CollectionShareModel.reasonText("newer-format", t))
        assertEquals(update, CollectionShareModel.reasonText("update-required", t))
        assertNull(CollectionShareModel.passwordProblem(SharePasswords.FIRST, SharePasswords.FIRST, t))
        assertNotNull(CollectionShareModel.passwordProblem("passwordpassword", "passwordpassword", t))
    }

    @Test fun a_missing_collection_says_so() = test {
        val m = model(device(), "00000000-0000-4000-8000-000000000000")
        assertNull(m.summary)
        assertEquals("That collection no longer exists.", m.error)
    }
}
