package app.localgatekeys.core.lan

import app.localgatekeys.core.group.GroupKey
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Base64Std
import app.localgatekeys.core.support.Vectors
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.Test

/** The discovery tag (desktop `sync.discovery`), pinned by `tests/vectors/sync/discovery.json`, and candidate selection. */
class DiscoveryTest {
    private val v: Map<String, JsonValue> = (Vectors.json(Vectors.sync("discovery.json")) as JsonValue.Obj).fields

    private fun str(x: JsonValue?): String = (x as JsonValue.Str).v
    private fun obj(x: JsonValue?): Map<String, JsonValue> = (x as JsonValue.Obj).fields
    private fun arr(x: JsonValue?): List<JsonValue> = (x as JsonValue.Arr).items

    private val groupKey = GroupKey(str(v["group_id"]), (v["epoch"] as JsonValue.Int).v, Base64Std.decodeStrict(str(v["group_key_b64"])))
    private val host = str(v["host_device_id"])

    @Test fun constants_match_the_vectors() {
        assertEquals(str(v["service_type"]), Discovery.SERVICE_TYPE)
        assertEquals(str(obj(v["txt"])["v"]), Discovery.TXT_VERSION)
    }

    @Test fun discovery_key_matches() {
        assertContentEquals(Base64Std.decodeStrict(str(v["discovery_key_b64"])), Discovery.discoveryKey(groupKey))
    }

    @Test fun tags_match_per_day() {
        val tags = arr(v["tags"])
        assertEquals(4, tags.size)
        for (t in tags) {
            val o = obj(t)
            assertEquals(str(o["tag"]), Discovery.tag(groupKey, host, str(o["day"])))
        }
    }

    @Test fun accepted_window_is_today_and_yesterday() {
        val w = obj(v["window"])
        val now = (w["now"] as JsonValue.Int).v
        assertEquals(arr(w["accepted"]).map { str(it) }.toSet(), Discovery.acceptedTags(groupKey, host, now))
        assertTrue(str(obj(v["txt"])["t"]) in Discovery.acceptedTags(groupKey, host, now))
        assertEquals(str(obj(v["txt"])["t"]), Discovery.tag(groupKey, host, Discovery.utcDay(now)))
    }

    @Test fun utc_day_formats() {
        assertEquals("1970-01-01", Discovery.utcDay(0))
        assertEquals("2026-10-29", Discovery.utcDay(1_793_232_000))
        assertEquals("2026-10-29", Discovery.utcDay(1_793_318_399))
        assertEquals("2026-10-28", Discovery.utcDay(1_793_231_999))
    }

    // ---- selection ----

    private val good = mapOf("v" to "1", "t" to "aaaa")
    private val accepted = setOf("aaaa", "bbbb")

    private fun ann(host: String, port: Int = 47821, txt: Map<String, String> = good) = Discovery.Announcement(host, port, txt)

    @Test fun keeps_matching_lan_announcements_in_order() {
        val got = Discovery.candidates(
            listOf(ann("192.168.1.23"), ann("10.0.0.5", 5000, mapOf("v" to "1", "t" to "bbbb"))), accepted, null,
        )
        assertEquals(listOf(LanEndpoint("192.168.1.23", 47821), LanEndpoint("10.0.0.5", 5000)), got)
    }

    @Test fun drops_wrong_tag_version_and_missing_fields() {
        val got = Discovery.candidates(
            listOf(
                ann("192.168.1.2", txt = mapOf("v" to "1", "t" to "zzzz")),
                ann("192.168.1.3", txt = mapOf("v" to "2", "t" to "aaaa")),
                ann("192.168.1.4", txt = mapOf("t" to "aaaa")),
                ann("192.168.1.5", txt = mapOf("v" to "1")),
            ),
            accepted, null,
        )
        assertEquals(emptyList<LanEndpoint>(), got)
    }

    @Test fun drops_non_lan_hosts_and_bad_ports() {
        val got = Discovery.candidates(
            listOf(
                ann("8.8.8.8"), ann("example.local"), ann("fe80::1%wlan0"), ann("::ffff:192.168.1.1"),
                ann("192.168.1.9", 0), ann("192.168.1.9", 65536), ann("192.168.1.9", -1),
            ),
            accepted, null,
        )
        assertEquals(emptyList<LanEndpoint>(), got)
    }

    @Test fun never_aims_at_loopback_link_local_or_ipv6() {
        val got = Discovery.candidates(
            listOf(
                ann("127.0.0.1"), ann("127.5.5.5"), ann("169.254.10.1"), ann("0.0.0.0"), ann("::1"),
                ann("fd00::5"), ann("192.168.1.023"), ann("192.168.1.256"),
            ),
            accepted, null,
        )
        assertEquals(emptyList<LanEndpoint>(), got)
        assertTrue(Discovery.routable("192.168.1.23"))
        assertTrue(Discovery.routable("10.1.2.3"))
        assertTrue(Discovery.routable("172.16.0.9"))
    }

    @Test fun deduplicates_excludes_the_pinned_address_and_caps_at_four() {
        val pinned = LanEndpoint("192.168.1.1", 47821)
        val found = listOf(ann("192.168.1.1"), ann("192.168.1.2"), ann("192.168.1.2")) +
            (3..9).map { ann("192.168.1.$it") }
        val got = Discovery.candidates(found, accepted, pinned)
        assertEquals((2..5).map { LanEndpoint("192.168.1.$it", 47821) }, got)
        assertEquals(Discovery.MAX_CANDIDATES, got.size)
    }
}
