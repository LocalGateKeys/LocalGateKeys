package app.localgatekeys.android.i18n

import android.content.res.Resources
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes

/**
 * Resolves UI text from resources, so models and screens carry resource ids and never English literals.
 * [AndroidTxt] reads the device resources; JVM tests use an English-only implementation of the same interface.
 */
interface Txt {
    fun s(@StringRes id: Int, vararg args: Any): String
    fun plural(@PluralsRes id: Int, count: Int, vararg args: Any): String
}

class AndroidTxt(private val resources: Resources) : Txt {
    override fun s(@StringRes id: Int, vararg args: Any): String = resources.getString(id, *args)
    override fun plural(@PluralsRes id: Int, count: Int, vararg args: Any): String =
        resources.getQuantityString(id, count, *args)
}
