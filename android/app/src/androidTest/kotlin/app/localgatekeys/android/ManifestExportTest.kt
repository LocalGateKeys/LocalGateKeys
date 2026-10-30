package app.localgatekeys.android

import android.content.ComponentName
import android.content.pm.PackageManager
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The installed app exposes one entry point, MainActivity, plus the permission-guarded system services (debug builds add PreviewActivity). */
class ManifestExportTest {
    @Test fun only_main_activity_is_exported() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_SERVICES or PackageManager.GET_PROVIDERS
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, flags)
        val exported = buildList {
            info.activities.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.receivers.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.services.orEmpty().filter { it.exported }.forEach { add(it.name) }
            info.providers.orEmpty().filter { it.exported }.forEach { add(it.name) }
        }.filterNot { it == "androidx.compose.ui.tooling.PreviewActivity" }
        // Part C: the two system services are exported for the system to bind, each behind its bind permission.
        // The provider is disabled below Android 14 (it is then not listed).
        val services = buildMap {
            put("app.localgatekeys.android.autofill.LgkAutofillService", "android.permission.BIND_AUTOFILL_SERVICE")
            if (android.os.Build.VERSION.SDK_INT >= 34) {
                put("app.localgatekeys.android.passkey.LgkCredentialProviderService", "android.permission.BIND_CREDENTIAL_PROVIDER_SERVICE")
            }
        }
        assertEquals(listOf("app.localgatekeys.android.MainActivity") + services.keys, exported)
        for ((name, permission) in services) {
            assertEquals(name, permission, info.services.orEmpty().first { it.name == name }.permission)
        }
        // The autofill, save and passkey sheets open only through this app's own PendingIntents.
        for (sheet in listOf("autofill.FillAuthActivity", "autofill.SaveLoginActivity", "passkey.PasskeyActivity")) {
            assertFalse(sheet, info.activities.orEmpty().first { it.name == "app.localgatekeys.android.$sheet" }.exported)
        }
        assertFalse(info.receivers.orEmpty().any { it.name.contains("ProfileInstallReceiver") })
    }

    /**
     * EmojiCompat's startup initializer is removed: it fetches emoji fonts through Google Play services' downloadable
     * fonts (Global Constraints: no Play services but Billing). Emoji render with the system font.
     */
    @Test fun emoji_compat_initializer_is_removed() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val provider = ctx.packageManager.getProviderInfo(
            ComponentName(ctx, "androidx.startup.InitializationProvider"), PackageManager.GET_META_DATA,
        )
        val keys = provider.metaData?.keySet().orEmpty()
        assertFalse(keys.toString(), "androidx.emoji2.text.EmojiCompatInitializer" in keys)
        // The other startup initializers stay (lifecycle is needed by the lock).
        assertTrue(keys.toString(), "androidx.lifecycle.ProcessLifecycleInitializer" in keys)
    }

    /** Ruling 23: Play Billing's telemetry uploader and the unused Play services modules are excluded from the build. */
    @Test fun no_google_telemetry_or_play_services_components() {
        val ctx = InstrumentationRegistry.getInstrumentation().targetContext
        val flags = PackageManager.GET_ACTIVITIES or PackageManager.GET_RECEIVERS or
            PackageManager.GET_SERVICES or PackageManager.GET_PROVIDERS
        val info = ctx.packageManager.getPackageInfo(ctx.packageName, flags)
        val all = info.activities.orEmpty().map { it.name } + info.receivers.orEmpty().map { it.name } +
            info.services.orEmpty().map { it.name } + info.providers.orEmpty().map { it.name }
        assertEquals(emptyList<String>(), all.filter { it.startsWith("com.google.android.datatransport") })
        assertEquals(emptyList<String>(), all.filter { it.endsWith("GoogleApiActivity") })
        // The class itself is not in the app either.
        val loaded = try {
            Class.forName("com.google.android.datatransport.runtime.TransportRuntime")
            true
        } catch (e: ClassNotFoundException) {
            false
        }
        assertFalse(loaded)
    }
}
