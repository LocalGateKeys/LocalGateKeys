package app.localgatekeys.android.security

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt
import app.localgatekeys.core.keyring.Keyring
import java.time.Instant
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * Printable vault health report (desktop `health_report.py`, sub-plan 12): one page of non-secret facts. Never an
 * item title, username, URL or secret: only the KDF parameters and the counts/ages the caller passes in [Facts].
 */
object HealthReport {
    /** Every value is display text; null means "not recorded". */
    data class Facts(
        val generatedAt: Long,
        val kdfMemoryKib: Long = Keyring.KDF_MEMORY_KIB,
        val kdfTime: Long = Keyring.KDF_ITERATIONS,
        val kdfLanes: Long = Keyring.KDF_PARALLELISM,
        val factors: String? = null,
        val backupAge: String? = null,
        val restoreTest: String? = null,
        val devices: String? = null,
        val lastSync: String? = null,
        val accessLog: String? = null,
        val breachFilterAge: String? = null,
        val build: String? = null,
        val licence: String? = null,
    )

    /**
     * The "Unlock factors" value from the phone's real settings: without the app password the phone's screen lock opens
     * the vault; with it, the app password plus fingerprint/face, key file and YubiKey when set.
     */
    fun factorsText(appPasswordOn: Boolean, biometric: Boolean, keyFile: Boolean, yubiKey: Boolean, t: Txt): String {
        if (!appPasswordOn) return t.s(R.string.health_report_factor_screen_lock)
        val parts = mutableListOf(t.s(R.string.health_report_factor_password))
        if (biometric) parts += t.s(R.string.health_report_factor_biometric)
        if (keyFile) parts += t.s(R.string.health_report_factor_key_file)
        if (yubiKey) parts += t.s(R.string.health_report_factor_yubikey)
        return parts.joinToString(", ")
    }

    /** The report rows (label, value), in the desktop's order. */
    fun rows(f: Facts, t: Txt): List<Pair<String, String>> {
        val unknown = t.s(R.string.health_report_unknown)
        fun v(s: String?) = s?.takeIf { it.isNotBlank() } ?: unknown
        val when_ = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm 'UTC'").withZone(ZoneOffset.UTC).format(Instant.ofEpochSecond(f.generatedAt))
        return listOf(
            t.s(R.string.health_report_generated) to when_,
            t.s(R.string.health_report_kdf) to t.s(R.string.health_report_kdf_value, (f.kdfMemoryKib / 1024).toInt(), f.kdfTime.toInt(), f.kdfLanes.toInt()),
            t.s(R.string.health_report_factors) to v(f.factors),
            t.s(R.string.health_report_backup_age) to v(f.backupAge),
            t.s(R.string.health_report_restore_test) to v(f.restoreTest),
            t.s(R.string.health_report_devices) to v(f.devices),
            t.s(R.string.health_report_last_sync) to v(f.lastSync),
            t.s(R.string.health_report_access_log) to v(f.accessLog),
            t.s(R.string.health_report_breach_filter) to v(f.breachFilterAge),
            t.s(R.string.health_report_build) to v(f.build),
            t.s(R.string.health_report_licence) to v(f.licence),
        )
    }
}
