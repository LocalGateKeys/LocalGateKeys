package app.localgatekeys.android.sync

import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.records.Namespace
import app.localgatekeys.core.records.SyncMeta
import app.localgatekeys.core.records.Wrapper
import app.localgatekeys.core.sync.StoreSnapshot
import app.localgatekeys.core.sync.SyncGroupState
import java.io.File
import org.junit.Assert.assertEquals
import org.junit.Test

/** The Wi-Fi run offers the emergency access plan only to a peer that answered `heir-hello` (desktop `heir_peers`). */
class HeirLanViewTest {
    private val v: Map<String, JsonValue> = run {
        val repo = System.getProperty("lgk.repoRoot") ?: error("lgk.repoRoot is not set")
        (CanonicalJson.parse(File(repo, "tests/vectors/heir/v1.json").readBytes()) as JsonValue.Obj).fields
    }

    @Test fun the_plan_goes_only_to_heir_peers() {
        val gk = SyncVectors.lanGroupKey()
        val me = SyncVectors.identity("B")
        val peer = SyncVectors.identity("A").deviceId
        val plan = v.getValue("wrapper")
        val note = Wrapper.make(Namespace.ITEM, JsonValue.Obj(mapOf("id" to JsonValue.Str("n1"), "kind" to JsonValue.Str("note"), "title" to JsonValue.Str("Note"))))
        val records = mapOf("heir:plan" to plan, "n1" to note)
        val snap = StoreSnapshot(records, records.mapValues { (_, w) -> SyncMeta.live(w, mapOf(me.deviceId to 1L)) })
        val state = SyncGroupState(gk.groupId, 1, gk.key, me, "install", hasFolder = false)
        assertEquals(listOf("n1"), lanLocalView(snap, state, peer, documents = false, now = 1_800_000_000).map { it.itemId })
        val advertised = state.copy(heirPeers = listOf(peer))
        assertEquals(listOf("heir:plan", "n1"), lanLocalView(snap, advertised, peer, documents = false, now = 1_800_000_000).map { it.itemId }.sorted())
        // Another peer of the same group still gets no plan.
        assertEquals(listOf("n1"), lanLocalView(snap, advertised, "someone-else", documents = false, now = 1_800_000_000).map { it.itemId })
    }
}
