package app.localgatekeys.android.recovery

import app.localgatekeys.android.R
import app.localgatekeys.android.i18n.Txt

/**
 * Estate pack (desktop `estate_pack.py` and the `builtin.estate` template, sub-plan 12): a note with one heading per
 * field; the "Shard holders" heading lists the emergency-access holders by nickname only.
 */
object EstatePack {
    const val TEMPLATE_ID = "builtin.estate"

    /** One template field: [name] as on the desktop, [label] its English label, [labelRes] the translated one. */
    data class Field(val name: String, val label: String, val labelRes: Int, val multiline: Boolean, val secret: Boolean)

    val FIELDS: List<Field> = listOf(
        Field("will_location", "Where the will is", R.string.estate_field_will_location, multiline = true, secret = false),
        Field("executor", "Executor", R.string.estate_field_executor, multiline = false, secret = false),
        Field("accounts_to_close", "Accounts to close", R.string.estate_field_accounts_to_close, multiline = true, secret = false),
        Field("devices_unlock", "Devices and their unlock", R.string.estate_field_devices_unlock, multiline = true, secret = true),
        Field("shard_holders", "Shard holders", R.string.estate_field_shard_holders, multiline = true, secret = false),
    )

    /** The note body: `## <label>` per field with room under it; holders listed by nickname. [t] null: English labels. */
    fun body(holders: List<String> = emptyList(), t: Txt? = null): String {
        val names = holders.map { it.trim() }.filter { it.isNotEmpty() }
        return FIELDS.joinToString("\n") { f ->
            val label = t?.s(f.labelRes) ?: f.label
            buildString {
                append("## ").append(label).append('\n')
                if (f.name == "shard_holders") for (n in names) append("- ").append(n).append('\n')
            }
        }
    }
}
