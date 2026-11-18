package app.localgatekeys.android.settings

import app.localgatekeys.android.unlock.KeyFileRef
import kotlinx.coroutines.flow.StateFlow

/** What Settings › Key file and YubiKey shows (Task 9). Nothing in it is secret. */
data class FactorState(
    /** The factors attach to the app password: without it the rows are hidden. */
    val passwordOn: Boolean = false,
    val keyFile: Boolean = false,
    /** The YubiKey's slot; null: no YubiKey. */
    val yubiKeySlot: Int? = null,
    val alwaysAsk: Boolean = false,
    /** "Remember the key file location on this phone". */
    val remember: Boolean = true,
    /** The remembered key file's name; null: none remembered (it is asked for when needed). */
    val rememberedKeyFile: String? = null,
) {
    val any: Boolean get() = keyFile || yubiKeySlot != null
}

/**
 * Settings › Key file and YubiKey over the app password (Task 9). MainActivity builds it over
 * [app.localgatekeys.android.unlock.AppPasswordController] and the open vault's local key. Each change takes the current
 * app password as typed (never stored) and, when a key file is set but not remembered, the key file to use ([keyFile]).
 * A YubiKey that is set, or added, is asked for while [yubiKeyPrompt] shows its slot.
 */
class FactorSeams(
    val state: suspend () -> FactorState,
    /** Adds (or replaces) the key file at [file]; [remember] keeps its location for unlocking. */
    val addKeyFile: suspend (password: String, file: KeyFileRef, remember: Boolean, keyFile: KeyFileRef?) -> Unit,
    /** Writes a new KeePass XML 2.0 key file to [file] (a document the person just created), then adds it. */
    val createKeyFile: suspend (password: String, file: KeyFileRef, remember: Boolean, keyFile: KeyFileRef?) -> Unit,
    val addYubiKey: suspend (password: String, slot: Int, keyFile: KeyFileRef?) -> Unit,
    val removeKeyFile: suspend (password: String, keyFile: KeyFileRef?) -> Unit,
    val removeYubiKey: suspend (password: String, keyFile: KeyFileRef?) -> Unit,
    val setAlwaysAsk: suspend (Boolean) -> Unit,
    val setRemember: suspend (Boolean) -> Unit,
    /** The slot of the YubiKey being waited for; null when none is. */
    val yubiKeyPrompt: StateFlow<Int?>,
    val cancelYubiKey: () -> Unit,
    /** The system file picker stops the app: the lock allows that one trip (Ruling 21). False: locked meanwhile. */
    val willOpenPicker: () -> Unit,
    val pickerClosed: () -> Boolean,
    /** A picked document's display name (its grant is persisted only once the change worked and it is remembered). */
    val describe: (uri: android.net.Uri) -> KeyFileRef,
    /** A picked document that was not used (the dialog was cancelled): any grant it holds is given back. */
    val discard: (KeyFileRef) -> Unit,
) {
    override fun toString(): String = "FactorSeams"
}
