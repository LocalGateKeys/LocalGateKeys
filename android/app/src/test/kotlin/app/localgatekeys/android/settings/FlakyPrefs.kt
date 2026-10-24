package app.localgatekeys.android.settings

import android.content.SharedPreferences

/**
 * SharedPreferences as Android implements commit(): the in-memory map is updated first, then the file is written,
 * and commit() returns false when the file write fails ([failCommit] decides per pending change). [disk] is what
 * survived. apply() updates memory and (here) the disk.
 */
class FlakyPrefs : SharedPreferences {
    val memory = HashMap<String, Any?>()
    val disk = HashMap<String, Any?>()
    /** Called with the pending (key, value) changes of a commit; true fails its disk write. A null value is a removal. */
    var failCommit: (Map<String, Any?>) -> Boolean = { false }

    private fun applyTo(map: MutableMap<String, Any?>, changes: Map<String, Any?>) {
        for ((k, v) in changes) if (v == null) map.remove(k) else map[k] = v
    }

    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        val changes = LinkedHashMap<String, Any?>()
        override fun putString(key: String, value: String?) = apply { changes[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = apply { changes[key] = values }
        override fun putInt(key: String, value: Int) = apply { changes[key] = value }
        override fun putLong(key: String, value: Long) = apply { changes[key] = value }
        override fun putFloat(key: String, value: Float) = apply { changes[key] = value }
        override fun putBoolean(key: String, value: Boolean) = apply { changes[key] = value }
        override fun remove(key: String) = apply { changes[key] = null }
        override fun clear() = apply { memory.keys.forEach { changes[it] = null } }
        override fun commit(): Boolean {
            applyTo(memory, changes) // memory first, as Android does
            if (failCommit(changes)) return false
            applyTo(disk, changes)
            return true
        }
        override fun apply() {
            applyTo(memory, changes)
            applyTo(disk, changes)
        }
    }

    override fun getAll(): MutableMap<String, *> = HashMap(memory)
    override fun getString(key: String, defValue: String?) = memory[key] as? String ?: defValue
    @Suppress("UNCHECKED_CAST")
    override fun getStringSet(key: String, defValues: MutableSet<String>?) = memory[key] as? MutableSet<String> ?: defValues
    override fun getInt(key: String, defValue: Int) = memory[key] as? Int ?: defValue
    override fun getLong(key: String, defValue: Long) = memory[key] as? Long ?: defValue
    override fun getFloat(key: String, defValue: Float) = memory[key] as? Float ?: defValue
    override fun getBoolean(key: String, defValue: Boolean) = memory[key] as? Boolean ?: defValue
    override fun contains(key: String) = memory.containsKey(key)
    override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
    override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener?) {}
}
