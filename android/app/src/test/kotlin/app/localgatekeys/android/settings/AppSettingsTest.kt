package app.localgatekeys.android.settings

import app.localgatekeys.android.i18n.EnglishTxt
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Port of AppSettingsTests.swift and AuroraTests.test_initials_setting_round_trips_and_is_capped. */
class AppSettingsTest {
    @Test fun defaults() {
        val s = AppSettings(MemoryStore())
        assertEquals(AutoLockDelay.IMMEDIATELY, s.autoLockDelay)
        assertEquals(IdleLock.FIVE_MINUTES, s.idleLock)
        assertEquals(300L, s.idleLock.limit)
        assertEquals(ClipboardExpiry.SIXTY_SECONDS, s.clipboardExpiry)
        assertEquals(60L, s.clipboardExpiry.seconds)
        assertTrue(s.concealSecretsInDetail)
        assertTrue(s.showCodesRow)
        assertTrue(s.copyCodeOnFill)
        assertEquals(Appearance.SYSTEM, s.appearance)
        assertNull(s.generatorOptions)
        assertFalse(s.erasePending)
        assertNull(s.planFullRevision)
        assertEquals("", s.initials)
    }

    @Test fun choices() {
        assertEquals(listOf(0L, 60L, 300L, 900L, 3600L), AutoLockDelay.entries.map { it.seconds })
        assertEquals(listOf<Long?>(60, 300, 900, 1800, null), IdleLock.entries.map { it.limit })
        assertEquals(listOf(30L, 60L, 120L, 300L), ClipboardExpiry.entries.map { it.seconds })
        assertEquals(
            listOf("Immediately", "After 1 minute", "After 5 minutes", "After 15 minutes", "After 1 hour"),
            AutoLockDelay.entries.map { it.label(EnglishTxt()) },
        )
        assertEquals(listOf("1 minute", "5 minutes", "15 minutes", "30 minutes", "Never"), IdleLock.entries.map { it.label(EnglishTxt()) })
        assertEquals(listOf("30 seconds", "60 seconds", "2 minutes", "5 minutes"), ClipboardExpiry.entries.map { it.label(EnglishTxt()) })
        assertEquals(listOf("System", "Light", "Dark"), Appearance.entries.map { it.label(EnglishTxt()) })
    }

    @Test fun round_trip_through_the_store() {
        val d = MemoryStore()
        val s = AppSettings(d)
        s.autoLockDelay = AutoLockDelay.ONE_HOUR; s.idleLock = IdleLock.NEVER; s.clipboardExpiry = ClipboardExpiry.FIVE_MINUTES
        s.concealSecretsInDetail = false; s.showCodesRow = false; s.copyCodeOnFill = false
        s.appearance = Appearance.DARK; s.generatorOptions = "{\"length\":20}"
        s.erasePending = true; s.planFullRevision = 7
        val r = AppSettings(d)
        assertEquals(AutoLockDelay.ONE_HOUR, r.autoLockDelay); assertEquals(IdleLock.NEVER, r.idleLock)
        assertNull(r.idleLock.limit)
        assertEquals(ClipboardExpiry.FIVE_MINUTES, r.clipboardExpiry)
        assertFalse(r.concealSecretsInDetail); assertFalse(r.showCodesRow); assertFalse(r.copyCodeOnFill)
        assertEquals(Appearance.DARK, r.appearance); assertEquals("{\"length\":20}", r.generatorOptions)
        assertTrue(r.erasePending); assertEquals(7L, r.planFullRevision)
        r.generatorOptions = null; r.planFullRevision = null
        assertNull(s.generatorOptions); assertNull(s.planFullRevision)
    }

    @Test fun reads_the_value_another_instance_wrote() {
        val d = MemoryStore()
        val s = AppSettings(d)
        AppSettings(d).copyCodeOnFill = false
        assertFalse(s.copyCodeOnFill)
    }

    @Test fun unknown_stored_values_fall_back_to_defaults() {
        val d = MemoryStore()
        d.putLong(AppSettings.Key.AUTO_LOCK_DELAY, 7); d.putLong(AppSettings.Key.IDLE_LOCK, -3)
        d.putLong(AppSettings.Key.CLIPBOARD_EXPIRY, 5); d.putString(AppSettings.Key.APPEARANCE, "x")
        val s = AppSettings(d)
        assertEquals(AutoLockDelay.IMMEDIATELY, s.autoLockDelay); assertEquals(IdleLock.FIVE_MINUTES, s.idleLock)
        assertEquals(ClipboardExpiry.SIXTY_SECONDS, s.clipboardExpiry); assertEquals(Appearance.SYSTEM, s.appearance)
    }

    @Test fun wrong_typed_values_fall_back_to_defaults() {
        val d = MemoryStore()
        d.putString(AppSettings.Key.AUTO_LOCK_DELAY, "300"); d.putLong(AppSettings.Key.SHOW_CODES_ROW, 0)
        val s = AppSettings(d)
        assertEquals(AutoLockDelay.IMMEDIATELY, s.autoLockDelay); assertTrue(s.showCodesRow)
    }

    @Test fun import_card_not_now_is_remembered() {
        val d = MemoryStore()
        assertFalse(AppSettings(d).importCardDismissed)
        AppSettings(d).importCardDismissed = true
        assertTrue(AppSettings(d).importCardDismissed)
    }

    @Test fun keys_match_the_iphone_names_and_omit_ios_only_ones() {
        assertEquals(
            listOf(
                "autoLockDelaySeconds", "settings.idleLockSeconds", "settings.clipboardExpirySeconds",
                "settings.concealFieldsInDetail", "settings.showCodesRow", "settings.copyCodeOnFill", "settings.appearance",
                "settings.generatorOptions", "settings.erasePending", "settings.initials", "settings.planFullRevision",
                "settings.listSort", "settings.listFavoritesFirst", "settings.importCardDismissed",
                "settings.unlockFailures", "settings.unlockFailureAt",
                "settings.unlockFailureUptime", "settings.unlockFailureBoot",
                // Workstream 4 setup progress (the iPhone's names once it gains onboarding).
                "settings.setupDone", "settings.setupSeen", "settings.setupCardHidden",
                // Part C autofill and passkey switches.
                "settings.autofillSuggestions", "settings.passkeyProvider",
            ),
            AppSettings.Key.all,
        )
        for (k in listOf("showWebsiteIcons", "QuickType", "quickTypeExactSites", "offerPasskeys", "quickTypeCleanupPending")) {
            assertTrue(k, AppSettings.Key.all.none { it.contains(k) })
        }
    }

    /** Key names hold none of the words the secret scan flags. */
    @Test fun key_names_hold_no_flagged_words() {
        for (k in AppSettings.Key.all) {
            for (bad in listOf("localgatekeys", "lgk", "vault", "secret", "password", "localkey", "groupkey", "identity", "keyring", "bookmark", "counter")) {
                assertFalse(k, k.lowercase().contains(bad))
            }
        }
    }

    @Test fun initials_setting_round_trips_and_is_capped() {
        val d = MemoryStore()
        val s = AppSettings(d)
        assertEquals("", s.initials)
        s.initials = "ilias"
        assertEquals("IL", AppSettings(d).initials)
        s.initials = "12"
        assertEquals("", AppSettings(d).initials)
    }

    @Test fun avatar_initials_table() {
        assertNull(AvatarInitials.from(""))
        assertNull(AvatarInitials.from("  "))
        assertNull(AvatarInitials.from("12"))
        assertEquals("IP", AvatarInitials.from("ip"))
        assertEquals("IP", AvatarInitials.from(" i p "))
        assertEquals("IP", AvatarInitials.from("Ilias Pel"))
        assertEquals("AB", AvatarInitials.from("a1 b2 c3"))
        assertEquals("AB", AvatarInitials.from("abc"))
        assertEquals("\u00C9", AvatarInitials.from("\u00E9"))
    }

    @Test fun avatar_initials_ada_lovelace() {
        assertEquals("AL", AvatarInitials.from("Ada Lovelace"))
    }

    @Test fun avatar_initials_split_on_unicode_whitespace() {
        assertEquals("AL", AvatarInitials.from("Ada\u00A0Lovelace"))
        assertEquals("AL", AvatarInitials.from("Ada\u3000Lovelace"))
        assertEquals("AL", AvatarInitials.from("Ada\u2003Lovelace"))
        assertEquals("AL", AvatarInitials.from("Ada\tLovelace"))
    }

    @Test fun avatar_initials_do_not_split_on_separator_controls() {
        // U+001C..U+001F are not whitespace in Swift and not letters: dropped, so "A?da" stays one word.
        for (c in listOf("\u001C", "\u001D", "\u001E", "\u001F")) {
            assertEquals("AD", AvatarInitials.from("A" + c + "da"))
        }
    }

    @Test fun avatar_initials_count_supplementary_letters_as_one() {
        val a = "\uD835\uDCD0" // MATHEMATICAL BOLD SCRIPT CAPITAL A
        val i = "\uD801\uDC00" // DESERET CAPITAL LETTER LONG I
        assertEquals(a + "B", AvatarInitials.from(a + "b"))
        assertEquals(a + i, AvatarInitials.from(a + " " + i))
        assertEquals(a + i, AvatarInitials.from(a + i + "x"))
    }

    @Test fun avatar_initials_keep_a_combining_mark_with_its_letter() {
        val eAcute = "e\u0301" // e + COMBINING ACUTE ACCENT
        assertEquals("E\u0301", AvatarInitials.from(eAcute))
        assertEquals("E\u0301A", AvatarInitials.from(eAcute + "a"))
        assertEquals("E\u0301B", AvatarInitials.from(eAcute + " b"))
    }

    @Test fun memory_store_is_safe_across_eight_threads() {
        val m = MemoryStore()
        val threads = (0 until 8).map { t -> Thread { for (n in 0 until 500) m.putLong("k$t-$n", n.toLong()) } }
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        for (t in 0 until 8) for (n in 0 until 500) assertEquals(n.toLong(), m.getLong("k$t-$n"))
    }
}
