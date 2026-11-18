package app.localgatekeys.core.sync

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.group.ViewFile
import app.localgatekeys.core.group.ViewSignature
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.keyring.Keyring
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.DetRand
import app.localgatekeys.core.support.FixedClock
import app.localgatekeys.core.support.MemoryFolder
import app.localgatekeys.core.support.MemoryStore
import app.localgatekeys.core.support.MergeVectors
import app.localgatekeys.core.support.MergeVectors.arr
import app.localgatekeys.core.support.MergeVectors.obj
import app.localgatekeys.core.support.MergeVectors.str
import app.localgatekeys.core.support.SyncFixtures.devPath
import app.localgatekeys.core.support.Vectors
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The cross-platform folder check (sub-plan 07 Task 5n), `tests/vectors/share/collections/folder.json`: device A's
 * personal sync folder written by the desktop (`folder/a`: keyring, signed view with two collections, memberships and
 * a share link, capability files). This core joins it as device B with the password (the Argon2id output comes from
 * the vector), runs once more, and must then hold the catalog, memberships and link the desktop's B holds
 * (`expected_b`) and publish A's states unchanged.
 *
 * B's files (everything this core wrote or changed in the folder) are `folder/from_android/`: the desktop's device A
 * reads them back to the same state in `tests/test_share_collection_vectors.py`. `LGK_WRITE_FROM_ANDROID=1`
 * rewrites them; otherwise the bytes must equal the committed files. One `DetRand(b_run.rand)` stream feeds the join,
 * both runs and the capability, heartbeat and witness files (`witnessRandom`), the one order the Swift core uses
 * for its single stream, so Swift `CollectionInteropTests` must write the same bytes except its hedged CryptoKit
 * signatures (checked on a Mac, docs/PENDING.md).
 */
class CollectionInteropTest {
    private val doc: Map<String, JsonValue> = obj(Vectors.json(Vectors.shareCollections("folder.json")))
    private val syncDir = str(doc["sync_dir"])!!
    private val gk = GroupKey(str(doc["group_id"])!!, (doc["epoch"] as JsonValue.Int).v, Vectors.hex(str(doc["group_key_hex"])!!))
    private val run = obj(doc["b_run"])
    private val expected = obj(doc["expected_b"])

    private class Out(val folder: MemoryFolder, val input: Map<String, ByteArray>, val store: MemoryStore, val deviceId: String) {
        /** Every file B wrote or changed, by its path under the sync folder. */
        val written: Map<String, ByteArray>
            get() = folder.files.filter { (path, data) -> input[path]?.contentEquals(data) != true }
    }

    private fun long(key: String): Long = (run[key] as JsonValue.Int).v

    /** A's folder, then B joins (password key from the vector) and runs once more. */
    private fun flow(): Out {
        val folder = MemoryFolder()
        for (rel in arr(doc["files"])) {
            val name = str(rel)!!
            folder.files["$syncDir/$name"] = Vectors.shareCollections("folder/a/$name").readBytes()
        }
        val input = folder.files.mapValues { it.value.copyOf() }
        val argon = obj(doc["argon2"])
        val password = str(doc["password"])!!
        val rand = DetRand(str(run["rand"])!!)
        val store = MemoryStore()
        val fs = FolderSync(folder, "android-interop", witnessRandom = rand, collections = true)
        val joined = fs.join(store, str(run["device_name"])!!, rand, FixedClock(long("join_at"))) { ring ->
            val salt = str(obj(obj(ring)["kdf"])["salt"])!!
            Vectors.hex(str(argon["$password|$salt"]) ?: error("no Argon2id output for salt $salt"))
        }
        assertEquals(emptyList(), joined.issues, "join")
        assertTrue(joined.wrote)
        val again = fs.runOnce(store, rand, FixedClock(long("run_at")))
        assertEquals(emptyList(), again.issues, "second run")
        return Out(folder, input, store, assertNotNull(store.snapshot.sync).deviceId)
    }

    @Test
    fun b_joins_the_desktop_folder_and_ends_like_the_desktop_b() {
        val out = flow()
        val snap = out.store.snapshot
        val catalog = CollectionCatalog.collections(snap).associate {
            it.id to JsonValue.Obj(mapOf("name" to JsonValue.Str(it.name), "description" to JsonValue.Str(it.description)))
        }
        assertEquals(obj(expected["catalog"]), catalog)
        val memberships = snap.itemRecords.keys.associateWith { CollectionCatalog.memberships(it, snap) }
            .filterValues { it.isNotEmpty() }
        assertEquals(obj(expected["memberships"]).mapValues { (_, v) -> arr(v).map { str(it)!! } }, memberships)
        val links = snap.records.filterKeys { it.startsWith(CollectionStates.LINK_PREFIX) }.map { (_, w) ->
            val r = obj(obj(w)["record"])
            str(r["collection_id"])!! to JsonValue.Obj(mapOf("mode" to r["mode"]!!, "role" to r["role"]!!))
        }.toMap()
        assertEquals(obj(expected["links"]), links)
        assertEquals(arr(expected["items"]).map { str(it)!! }, snap.itemRecords.keys.sorted())

        // B's view republishes A's states unchanged, signed with the key the keyring lists for B.
        val raw = assertNotNull(out.folder.files[devPath(out.deviceId)])
        val (header, states) = ViewFile.decode(raw, gk, out.deviceId)
        assertEquals(arr(doc["a_states"]).map(MergeVectors::state), states)
        val ring = Keyring.parse(assertNotNull(out.folder.files["$syncDir/keyring.lgkkeys"]))
        val identity = assertNotNull(snap.sync).identity
        val key = assertNotNull(Keyring.memberSigningKeys(ring)[out.deviceId])
        assertEquals(key, Base64Std.encode(identity.signingPublicKey))
        val sig = assertNotNull(out.folder.files["$syncDir/signatures/${out.deviceId}.lgksig"])
        assertContentEquals(ViewSignature.sign(raw, header, identity), sig)
        assertTrue(FolderSync(out.folder, "android-check").folderCapable(gk, out.deviceId, key, FeatureCapability.Feature.COLLECTIONS))
    }

    @Test
    fun writes_from_android_files() {
        val out = flow()
        val again = flow()
        assertEquals(out.deviceId, again.deviceId)
        assertEquals(out.folder.image(), again.folder.image(), "the same stream writes the same bytes")
        val written = out.written.mapKeys { (path, _) ->
            assertTrue(path.startsWith("$syncDir/"), path)
            path.removePrefix("$syncDir/")
        }
        assertTrue("devices/${out.deviceId}.lgksync" in written && "keyring.lgkkeys" in written, written.keys.toString())
        val dir = File(Vectors.root, "share/collections/folder/from_android")
        if (System.getenv("LGK_WRITE_FROM_ANDROID") == "1") {
            dir.deleteRecursively()
            for ((rel, data) in written) {
                val f = File(dir, rel)
                f.parentFile.mkdirs()
                f.writeBytes(data)
            }
        }
        check(dir.isDirectory) { "vectors missing: $dir (generate with LGK_WRITE_FROM_ANDROID=1)" }
        val committed = dir.walkTopDown().filter { it.isFile }.associate { it.relativeTo(dir).invariantSeparatorsPath to it.readBytes() }
        assertEquals(written.keys.sorted(), committed.keys.sorted())
        for ((rel, data) in written) assertContentEquals(data, committed[rel], rel)
    }
}
