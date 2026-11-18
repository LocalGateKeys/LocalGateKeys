package app.localgatekeys.core.sync

import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.keyring.KeyringException
import app.localgatekeys.core.keyring.KeyringRotate
import app.localgatekeys.core.keyring.ShareKeyring
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.LanFeatures
import app.localgatekeys.core.lan.LanMessages
import app.localgatekeys.core.lan.LanSyncException
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.records.RecordException
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.QueueRandom
import app.localgatekeys.core.support.SyncFixtures
import app.localgatekeys.core.support.Vectors
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Shared collections (sub-plan 07 Task 5a) against the desktop's bytes in `tests/vectors/share/collections/`
 * (scripts/make_share_collection_vectors.py): share keyrings written and adopted, owner-signed removal, the share view,
 * personal collection states, the `.lgkcol` capability, the `features` message, Pro and read-only gating.
 */
class SharedCollectionTest {
    private val ring: Map<String, JsonValue> = Vectors.json(Vectors.shareCollections("keyring.json")).obj().fields
    private val yes: (String) -> Boolean = { true }
    private val gid = str(ring["group_id"])!!
    private val cid = str(ring["collection_id"])!!
    private val now = (ring["now"] as JsonValue.Int).v
    private val pin = ShareKeyring.Pin.of(case("create")["keyring"]!!)

    private fun id(who: String): DeviceIdentity = SyncFixtures.identity(who)

    private fun case(name: String): Map<String, JsonValue> = obj(ring[name])

    private fun queue(c: Map<String, JsonValue>) = QueueRandom(arr(c["random_reads_hex"]).map { Vectors.hex(str(it)!!) })

    private fun canonical(v: JsonValue): ByteArray = CanonicalJson.encode(v, Dialect.UTF8)

    private fun table(): KeyringRotate.KeyDerivation {
        val known = obj(ring["argon2"]).mapValues { Vectors.hex(str(it.value)!!) }
        return KeyringRotate.KeyDerivation { pw, salt -> known["$pw|${Base64Std.encode(salt)}"] ?: ByteArray(32) }
    }

    /** The Argon2id key of the share password with [keyring]'s salt. */
    private fun pwKey(keyring: JsonValue, password: String = str(ring["password"])!!): ByteArray {
        val salt = str(obj(obj(keyring)["kdf"])["salt"])!!
        return Vectors.hex(str(obj(ring["argon2"])["$password|$salt"])!!)
    }

    private fun gk1() = GroupKey(gid, 1, Vectors.hex(str(case("create")["group_key_hex"])!!))

    private fun reason(f: () -> Any?): String? = try {
        f()
        null
    } catch (e: KeyringException) {
        e.reason
    } catch (e: RecordException) {
        e.reason
    } catch (e: RemovalException) {
        e.reason
    } catch (e: LanSyncException) {
        e.reason
    }

    private fun ids(v: JsonValue?): Set<String> = arr(v).map { str(it)!! }.toSet()

    // ---- keyring writers, byte for byte ----

    @Test fun owner_creates_the_share_keyring_byte_for_byte() {
        val c = case("create")
        val random = queue(c)
        val spec = ShareKeyring.Spec(cid, str(ring["name"])!!, str(ring["shared_mode"])!!)
        // keyring.json describes share v1 (format 2): written only with the explicit legacy knob.
        val (created, gk) = ShareKeyring.create(
            str(ring["password"])!!, id("A"), "Owner phone", spec, random, now, yes, table(), ShareKeyring.LEGACY_SHARE_FORMAT,
        )
        assertTrue(random.isEmpty)
        assertContentEquals(canonical(c["keyring"]!!), canonical(created))
        assertEquals(gid, gk.groupId)
        assertContentEquals(Vectors.hex(str(c["group_key_hex"])!!), gk.key)
        assertEquals(str(ring["name"]), ShareKeyring.shareName(created, gk))
        assertEquals(ids(c["approved"]), ShareKeyring.approvedMembers(created))
        // The name never appears in the keyring's bytes.
        assertFalse(String(canonical(created), Charsets.UTF_8).contains("Family"))
        assertEquals(ShareKeyring.Pin(cid, id("A").deviceId, Base64Std.encode(id("A").signingPublicKey), "read"), pin)
    }

    @Test fun joins_and_approval_byte_for_byte() {
        val created = case("create")["keyring"]!!
        val b = case("join_b")
        val random = queue(b)
        val (joinedB, gkB) = ShareKeyring.join(created, pwKey(created), id("B"), "Bea", random, FixedClock(now + 60))
        assertTrue(random.isEmpty)
        assertContentEquals(canonical(b["keyring"]!!), canonical(joinedB))
        assertEquals(gk1(), gkB)
        assertEquals(listOf(id("B").deviceId), ShareKeyring.pending(joinedB, id("A").deviceId))

        val approved = ShareKeyring.approvePending(joinedB, gk1(), id("A"), listOf(id("B").deviceId))
        assertContentEquals(canonical(case("approve_b")["keyring"]!!), canonical(approved))
        assertEquals(ids(case("approve_b")["approved"]), ShareKeyring.approvedMembers(approved))

        val c = case("join_c")
        val rc = queue(c)
        val (joinedC, _) = ShareKeyring.join(approved, pwKey(approved), id("C"), "Cy", rc, FixedClock(now + 120))
        assertTrue(rc.isEmpty)
        assertContentEquals(canonical(c["keyring"]!!), canonical(joinedC))
        assertEquals(mapOf(id("A").deviceId to "Owner phone", id("B").deviceId to "Bea", id("C").deviceId to "Cy"), Keyring.memberNames(joinedC, gk1()))
    }

    @Test fun owner_removes_a_member_byte_for_byte_and_only_the_owner_notice_counts() {
        val joinedC = case("join_c")["keyring"]!!
        val r = case("remove_b")
        val random = queue(r)
        val remove = arr(r["remove"]).map { str(it)!! }
        val (rotated, gk2) = ShareKeyring.rotate(joinedC, gk1(), id("A"), str(ring["new_password"])!!, remove, random, yes, table())
        assertTrue(random.isEmpty)
        assertContentEquals(canonical(r["keyring"]!!), canonical(rotated))
        assertContentEquals(Vectors.hex(str(r["group_key_hex"])!!), gk2.key)
        assertEquals(2, gk2.epoch)
        assertEquals(str(ring["name"]), ShareKeyring.shareName(rotated, gk2))
        assertEquals(setOf(id("A").deviceId), ShareKeyring.approvedMembers(rotated))

        val issued = (r["notice_issued_at"] as JsonValue.Int).v
        val notice = Removal.makeNotice(id("A"), gid, id("B").deviceId, 2, issued)
        assertContentEquals(str(r["notice"])!!.toByteArray(Charsets.US_ASCII), notice)
        val ringBytes = canonical(rotated)
        val watchB = ShareAccess.removalWatch(gid, id("B").deviceId, 1, "", ".", pin)!!
        assertEquals(id("A").deviceId, Removal.verifyNotice(notice, watchB, ringBytes).signer)
        // remove_member in one step: B and the never-approved C go, the notice names B (the share v1 vector: no upgrade;
        // the app's removal upgrades, ShareGatingTest).
        val removed = ShareKeyring.removeMember(
            joinedC, gk1(), id("A"), id("B").deviceId, str(ring["new_password"])!!, queue(r), yes, issued, table(), upgrade = false,
        )
        assertContentEquals(canonical(r["keyring"]!!), canonical(removed.keyring))
        assertContentEquals(notice, removed.notice)
        assertEquals(remove, removed.dropped)
        assertEquals("not-owner", reason {
            ShareKeyring.removeMember(joinedC, gk1(), id("B"), id("C").deviceId, str(ring["new_password"])!!, DetRand("x"), yes, issued, table())
        })
        // The owner's device never acts on a notice; a member's notice is not the owner's.
        assertNull(ShareAccess.removalWatch(gid, id("A").deviceId, 1, "", ".", pin))
        val forged = case("forged_notice")
        val watchC = ShareAccess.removalWatch(gid, id("C").deviceId, 1, "", ".", pin)!!
        assertEquals(str(forged["reason"]), reason { Removal.verifyNotice(str(forged["notice"])!!.toByteArray(), watchC, ringBytes) })
    }

    @Test fun only_the_owner_changes_the_share() {
        val joinedC = case("join_c")["keyring"]!!
        val approved = case("approve_b")["keyring"]!!
        assertEquals("not-owner", reason { ShareKeyring.approve(joinedC, gk1(), id("B"), listOf(id("C").deviceId)) })
        assertEquals("not-owner", reason {
            ShareKeyring.rotate(joinedC, gk1(), id("B"), str(ring["new_password"])!!, listOf(id("C").deviceId), DetRand("b"), yes, table())
        })
        assertEquals("not-pending", reason { ShareKeyring.approvePending(approved, gk1(), id("A"), listOf(id("B").deviceId)) })
        assertEquals("not-pending", reason { ShareKeyring.approvePending(joinedC, gk1(), id("A"), emptyList()) })
        assertEquals("bad-metadata", reason {
            ShareKeyring.create("pw", id("A"), "x", ShareKeyring.Spec(cid.uppercase(), "Family", "read"), DetRand("s"), now, yes, table())
        })
        assertEquals("bad-metadata", reason {
            ShareKeyring.create("pw", id("A"), "x", ShareKeyring.Spec(cid, " Family", "read"), DetRand("s"), now, yes, table())
        })
        assertEquals("bad-metadata", reason {
            ShareKeyring.create("pw", id("A"), "x", ShareKeyring.Spec(cid, "Family", "write"), DetRand("s"), now, yes, table())
        })
    }

    // ---- device sync and shares stay apart ----

    @Test fun device_sync_refuses_a_share_keyring_and_a_share_refuses_a_device_sync_keyring() {
        val share = canonical(case("create")["keyring"]!!)
        assertEquals("share-group", reason { Keyring.parse(share) })
        assertEquals("share-group", reason { Keyring.accept(case("create")["keyring"]!!, gk1(), id("A")) })
        assertNotNull(ShareKeyring.parse(share))
        val personal = Vectors.sync("keyring_epoch1.json").readBytes()
        val parsed = ShareKeyring.parse(personal)
        assertEquals("not-share", reason { ShareKeyring.requireShare(parsed) })
        assertEquals("not-share", reason { ShareKeyring.join(parsed, ByteArray(32), id("C"), "Cy", DetRand("d"), FixedClock(now)) })
        // A collection state id is never an item id in device sync.
        val item = JsonValue.Obj(mapOf("ns" to JsonValue.Str("item"), "schema" to JsonValue.Int(1), "updated_at" to JsonValue.Int(0),
            "record" to JsonValue.Obj(mapOf("id" to JsonValue.Str("col:$cid"), "kind" to JsonValue.Str("note")))))
        assertEquals("bad-remote", reason { Wrapper.unwrap(ItemState("col:$cid", mapOf("x" to 1L), false, null, item), false) })
    }

    // ---- adopting: the negative and positive vectors ----

    @Test fun adopt_refuses_exactly_what_the_desktop_refuses() {
        for (c in arr(ring["negative"]).map { obj(it) }) {
            val trusted = GroupKey(gid, (c["trusted_epoch"] as JsonValue.Int).v, Vectors.hex(str(c["trusted_key_hex"])!!))
            val got = reason { ShareKeyring.adopt(c["stored"]!!, c["candidate"]!!, trusted, id(str(c["device"])!!), pin) }
            assertEquals(str(c["reason"]), got, str(c["name"]))
        }
        for (c in arr(ring["positive"]).map { obj(it) }) {
            val trusted = GroupKey(gid, (c["trusted_epoch"] as JsonValue.Int).v, Vectors.hex(str(c["trusted_key_hex"])!!))
            val gk = ShareKeyring.adopt(c["stored"]!!, c["candidate"]!!, trusted, id(str(c["device"])!!), pin)
            assertEquals((c["new_epoch"] as JsonValue.Int).v, gk.epoch, str(c["name"]))
            assertContentEquals(Vectors.hex(str(c["new_key_hex"])!!), gk.key, str(c["name"]))
            assertTrue(ShareKeyring.growsFrom(c["stored"]!!, c["candidate"]!!), str(c["name"]))
        }
        // The removed member: the rotation wraps no key for it.
        assertEquals("not-member", reason {
            ShareKeyring.adopt(case("join_c")["keyring"]!!, case("remove_b")["keyring"]!!, gk1(), id("B"), pin)
        })
        // Another pin (a different owner key) is tampering even for a genuine keyring.
        val other = pin.copy(ownerKey = Base64Std.encode(id("B").signingPublicKey))
        assertEquals("tampered", reason { ShareKeyring.adopt(case("join_b")["keyring"]!!, case("approve_b")["keyring"]!!, gk1(), id("B"), other) })
    }

    @Test fun owner_merges_a_join_that_raced_its_approval_and_a_lost_join_is_told_to_join_again() {
        val created = case("create")["keyring"]!!
        val joinedB = case("join_b")["keyring"]!!
        val approved = case("approve_b")["keyring"]!!
        // C joined from the folder's joined_b while the owner approved B on its own copy.
        val (racedC, _) = ShareKeyring.join(joinedB, pwKey(joinedB), id("C"), "Cy", DetRand("race"), FixedClock(now + 90))
        assertEquals("tampered", reason { ShareKeyring.adopt(approved, racedC, gk1(), id("A"), pin) })
        val merged = assertNotNull(ShareKeyring.reconcileOwner(approved, racedC, gk1(), id("A"), pin))
        assertEquals(setOf(id("A").deviceId, id("B").deviceId), ShareKeyring.approvedMembers(merged))
        assertEquals(listOf(id("C").deviceId), ShareKeyring.pending(merged, id("A").deviceId))
        ShareKeyring.checkSameEpochGrowth(approved, merged)
        assertNull(ShareKeyring.reconcileOwner(approved, racedC, gk1(), id("B"), pin)) // a member never re-signs

        // B and C joined from the same created keyring; C's keyring reached the folder.
        val (onlyC, _) = ShareKeyring.join(created, pwKey(created), id("C"), "Cy", DetRand("c-first"), FixedClock(now + 61))
        assertTrue(ShareKeyring.supersededJoin(joinedB, onlyC, gk1(), id("B"), pin))
        assertFalse(ShareKeyring.supersededJoin(joinedB, joinedB, gk1(), id("B"), pin))
        assertFalse(ShareKeyring.supersededJoin(created, onlyC, gk1(), id("A"), pin)) // never the owner
        // A folder keyring that also dropped someone else (B) is not a lost join, nor is another epoch.
        assertFalse(ShareKeyring.supersededJoin(case("join_c")["keyring"]!!, created, gk1(), id("C"), pin))
        assertFalse(ShareKeyring.supersededJoin(case("join_c")["keyring"]!!, case("remove_b")["keyring"]!!, gk1(), id("C"), pin))
    }

    // ---- the share view ----

    @Test fun share_view_publishes_only_the_collection_with_personal_fields_stripped() {
        val view = Vectors.json(Vectors.shareCollections("view.json")).obj().fields
        val c = str(view["collection_id"])!!
        val expected = arr(view["shared"]).map { obj(it) }
        val shared = arr(view["vault_items"]).filter { ShareView.isShared(it, c) }
        assertEquals(expected.map { str(it["id"]) }, shared.map { str(obj(it)["id"]) })
        for ((record, e) in shared.zip(expected)) {
            val w = ShareView.wrapper(record, c)
            assertContentEquals(canonical(e["wrapper"]!!), canonical(w), str(e["id"]))
            assertEquals(str(e["digest"]), SyncMeta.digest(w))
        }
        for (case in arr(view["incoming"]).map { obj(it) }) {
            val state = ItemState(str(case["id"])!!, mapOf(MergeB to 1L), false, null, case["wrapper"])
            val got = reason { ShareView.checkIncoming(state, c) } ?: "ok"
            assertEquals(str(case["verdict"]), got, str(case["name"]))
        }
        assertEquals(arr(view["share_local_only_item_fields"]).map { str(it) }, ShareView.LOCAL_ONLY_ITEM_FIELDS)
    }

    // ---- personal collection states ----

    @Test fun collection_states_match_the_desktop_and_malformed_ones_are_refused() {
        val doc = Vectors.json(Vectors.shareCollections("states.json")).obj().fields
        val prefixes = obj(doc["prefixes"])
        assertEquals(listOf(CollectionStates.CATALOG_PREFIX, CollectionStates.MEMBERSHIP_PREFIX, CollectionStates.LINK_PREFIX),
            listOf("catalog", "membership", "link").map { str(prefixes[it]) })
        for (v in arr(doc["valid"]).map { obj(it) }) {
            val sid = str(v["id"])!!
            val state = ItemState(sid, mapOf(MergeA to 1L), false, null, v["wrapper"])
            val record = CollectionStates.unwrap(state, isCopy = false)
            val rebuilt = when (str(record["kind"])) {
                "collection" -> CollectionStates.catalog(str(record["collection_id"])!!, str(record["name"])!!, str(record["description"])!!,
                    (record["created_at"] as JsonValue.Int).v, (record["updated_at"] as JsonValue.Int).v)
                "membership" -> CollectionStates.membership(str(record["item_id"])!!, arr(record["collection_ids"]).map { str(it)!! }.reversed())
                else -> CollectionStates.link(str(record["collection_id"])!!, str(record["mode"])!!, str(record["role"])!!)
            }
            val wrapper = CollectionStates.wrapper(rebuilt)
            assertContentEquals(canonical(v["wrapper"]!!), canonical(wrapper), sid)
            assertEquals(str(v["digest"]), SyncMeta.digest(wrapper), sid)
            assertEquals(sid, CollectionStates.stateId(rebuilt))
            // A phone without collections refuses them in device sync: quarantined, never stored.
            assertEquals("bad-remote", SyncRunner.check(state, emptyMap()), sid)
            // A conflict copy of a collection state names its state through its record.
            val copy = JsonValue.Obj(obj(v["wrapper"]) + ("id" to JsonValue.Str("8f1e2d3c-4b5a-4968-8776-655443322110")))
            CollectionStates.unwrap(ItemState("8f1e2d3c-4b5a-4968-8776-655443322110", mapOf(MergeA to 1L), false, null, copy), isCopy = true)
        }
        for (m in arr(doc["malformed"]).map { obj(it) }) {
            val state = ItemState(str(m["id"])!!, mapOf(MergeA to 1L), false, null, m["wrapper"])
            assertEquals(str(m["verdict"]), reason { CollectionStates.unwrap(state, isCopy = false) }, str(m["name"]))
        }
        val a = listOf("9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
        val b = listOf(cid, "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d")
        assertEquals(listOf(cid, "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"), CollectionStates.union(a, b))
        assertNull(CollectionStates.union((0 until 15).map { "%08d-0000-4000-8000-000000000000".format(it) }, (15 until 21).map { "%08d-0000-4000-8000-000000000000".format(it) }))
    }

    // ---- capability file and features message ----

    @Test fun lgkcol_capability_and_features_message() {
        val doc = Vectors.json(Vectors.shareCollections("capability.json")).obj().fields
        val gk = GroupKey(str(doc["group_id"])!!, (doc["epoch"] as JsonValue.Int).v, Vectors.hex(str(doc["group_key_hex"])!!))
        val a = id("A")
        val signer = Base64Std.encode(a.signingPublicKey)
        fun file(name: String) = obj(doc[name]).let { Base64Std.decodeStrict(str(it["file_b64"])!!) to Base64Std.decodeStrict(str(it["sig_b64"])!!) }
        val (col, colSig) = file("lgkcol")
        val (cap, capSig) = file("lgkcap")
        val f = FeatureCapability.Feature.COLLECTIONS
        val d = FeatureCapability.Feature.DOCUMENTS
        assertEquals(".lgkcol", f.suffix)
        assertEquals(str(obj(doc["suffixes"])["collections_sig"]), f.signatureSuffix)
        assertTrue(FeatureCapability.verify(col, colSig, gk, a.deviceId, signer, f))
        assertTrue(FeatureCapability.verify(cap, capSig, gk, a.deviceId, signer, d))
        // A file copied under the other name never counts; nor another signer or another device.
        assertFalse(FeatureCapability.verify(cap, capSig, gk, a.deviceId, signer, f))
        assertFalse(FeatureCapability.verify(col, colSig, gk, a.deviceId, signer, d))
        assertFalse(FeatureCapability.verify(col, colSig, gk, a.deviceId, Base64Std.encode(id("B").signingPublicKey), f))
        assertFalse(FeatureCapability.verify(col, colSig, gk, id("B").deviceId, signer, f))
        assertFalse(FeatureCapability.verify(col, colSig, gk, a.deviceId, null, f))
        val (mine, mineSig) = FeatureCapability.encode(gk, a, f, FixedClock(now), DetRand("cap"))
        assertTrue(FeatureCapability.verify(mine, mineSig, gk, a.deviceId, signer, f))

        assertContentEquals(str(doc["features_message"])!!.toByteArray(Charsets.US_ASCII), LanFeatures.encode(listOf(LanFeatures.COLLECTIONS)))
        assertEquals(listOf(LanFeatures.COLLECTIONS), arr(doc["features"]).map { str(it) })
        for (m in arr(doc["messages"]).map { obj(it) }) {
            val raw = str(m["raw"])!!.toByteArray(Charsets.UTF_8)
            assertEquals(str(m["verdict"]), reason { LanFeatures.parse(raw) } ?: "ok", str(m["name"]))
        }
        // The phone now claims the feature: the live parser reads a features message, and it lists collections.
        assertEquals(app.localgatekeys.core.lan.LanMessage.Features(listOf(LanFeatures.COLLECTIONS)), LanMessages.parse(LanFeatures.encode(listOf(LanFeatures.COLLECTIONS))))
        assertEquals(arr(doc["features"]).map { str(it) }, LanFeatures.OURS)
        for (m in arr(doc["messages"]).map { obj(it) }) {
            val raw = str(m["raw"])!!.toByteArray(Charsets.UTF_8)
            val live = reason { LanMessages.parse(raw) }
            if (str(m["verdict"]) == "ok") assertNull(live, str(m["name"])) else assertEquals(str(m["verdict"]), live, str(m["name"]))
        }
    }

    // ---- Pro and read-only ----

    @Test fun pro_gates_create_join_and_sync_but_never_removal() {
        for (a in listOf(ShareAccess.Action.CREATE, ShareAccess.Action.JOIN, ShareAccess.Action.SYNC)) {
            assertFailsWith<ShareProRequiredException> { ShareAccess.requirePro(a, isPro = false) }
            ShareAccess.requirePro(a, isPro = true)
        }
        for (a in listOf(ShareAccess.Action.REMOVE, ShareAccess.Action.APPROVE, ShareAccess.Action.LEAVE)) ShareAccess.requirePro(a, isPro = false)
    }

    @Test fun read_only_share_refuses_edits_moves_and_fails_closed() {
        val other = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d"
        val shares = listOf(
            ShareAccess.Membership(cid, "member", "read"),
            ShareAccess.Membership(other, "member", "edit"),
            ShareAccess.Membership("0f0f0f0f-0000-4000-8000-000000000000", "owner", "read"),
        )
        val readOnly = ShareAccess.readOnlyCollectionIds(shares, shares.map { it.collectionId }.toSet())
        assertEquals(setOf(cid), readOnly)
        assertEquals(shares.map { it.collectionId }.toSet(), ShareAccess.readOnlyCollectionIds(null, shares.map { it.collectionId }.toSet()))
        fun item(vararg c: String) = JsonValue.Obj(mapOf("collection_ids" to JsonValue.Arr(c.map { JsonValue.Str(it) })))
        assertFailsWith<ReadOnlyCollectionException> { ShareAccess.checkWritable(readOnly, item(cid)) }
        assertFailsWith<ReadOnlyCollectionException> { ShareAccess.checkWritable(readOnly, item(other), item(other, cid)) } // move in
        assertFailsWith<ReadOnlyCollectionException> { ShareAccess.checkWritable(readOnly, item(cid), item()) } // move out
        ShareAccess.checkWritable(readOnly, item(other), item(other))
        ShareAccess.checkWritable(readOnly, null, item())
        ShareAccess.checkWritable(emptySet(), item(cid))
    }

    private companion object {
        const val MergeA = "a1111111-0000-4000-8000-00000000000a"
        const val MergeB = "b2222222-0000-4000-8000-00000000000b"
    }
}
