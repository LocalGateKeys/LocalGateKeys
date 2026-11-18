package app.localgatekeys.android.recovery

import app.localgatekeys.android.i18n.EnglishTxt
import org.junit.Assert.assertEquals
import org.junit.Test

/** Desktop `estate_pack.body`: one "## <label>" per field, holders by nickname under Shard holders. */
class EstatePackTest {
    @Test fun body_without_holders_matches_the_desktop() {
        assertEquals(
            "## Where the will is\n\n## Executor\n\n## Accounts to close\n\n## Devices and their unlock\n\n## Shard holders\n",
            EstatePack.body(),
        )
    }

    @Test fun holders_are_listed_by_nickname_and_blanks_dropped() {
        val body = EstatePack.body(listOf(" Ann ", "", "Bob"), EnglishTxt())
        assertEquals(true, body.endsWith("## Shard holders\n- Ann\n- Bob\n"))
        assertEquals(listOf("will_location", "executor", "accounts_to_close", "devices_unlock", "shard_holders"), EstatePack.FIELDS.map { it.name })
        assertEquals(listOf("devices_unlock"), EstatePack.FIELDS.filter { it.secret }.map { it.name })
    }
}
