package app.localgatekeys.android.sync

import app.localgatekeys.android.pro.LicenseKeys
import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.android.vault.VaultCounterStore
import app.localgatekeys.core.lan.DeviceIdentity
import app.localgatekeys.core.lan.HelloCounterSource
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.SystemClock
import app.localgatekeys.core.primitives.SystemRandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay

/**
 * Called after every sync run and every local commit, so an autofill index can match the vault (the iPhone's
 * `AutoFillIdentityRefreshing` / QuickType). Android v1 has none: [NONE]. Kept as a seam for the autofill part.
 */
fun interface AutoFillIdentityRefreshing {
    suspend fun syncDidFinish(store: ItemStore)

    companion object {
        val NONE = AutoFillIdentityRefreshing { }
    }
}

/**
 * What the coordinator needs (Swift `SyncDependencies`). [slots]: only the sync slots of the unlocked vault (paired
 * peer, install id, peer counters, folder URI; the hello counter is the LAN transport's). [io]: where the blocking
 * folder, store and socket work runs (never the coordinator's own thread).
 */
data class SyncDependencies(
    val slots: SecretSlots,
    val folders: FolderOpening,
    val lan: LanTransporting,
    val autoFill: AutoFillIdentityRefreshing = AutoFillIdentityRefreshing.NONE,
    val random: RandomSource,
    val clock: UnixClock,
    val licenseKeys: Map<String, ByteArray>,
    val deviceName: String = SyncWording.DEVICE_NAME,
    val newIdentity: (RandomSource) -> DeviceIdentity = { DeviceIdentity.generate(random = it) },
    /** Waits before a sync triggered by an edit (debounce). */
    val sleep: suspend (Long) -> Unit = { delay(it) },
    val editDebounceMillis: Long = 2_000,
    /** This phone's Wi-Fi IPv4 subnet, read before a pairing dial (null: unknown, nothing is compared). */
    val localSubnet: () -> IPv4Subnet? = { null },
    val io: CoroutineDispatcher = Dispatchers.IO,
) {
    /** Never shows the slots, keys or licence keys. */
    override fun toString(): String = "SyncDependencies(deviceName=$deviceName, editDebounceMillis=$editDebounceMillis)"

    companion object {
        /**
         * The app's dependencies for one unlocked vault: one [HelloCounterSource] over that vault's sealed counter slots,
         * shared by every LAN exchange of the unlock (core rule: one source per counter store). The app passes its
         * socket transport as [lan] and its [SafFolderOpener] as [folders]; the defaults reach nothing and open no folder.
         */
        fun live(
            slots: SecretSlots,
            lan: (HelloCounterSource, RandomSource, UnixClock) -> LanTransporting = { _, _, _ -> LanTransporting.UNAVAILABLE },
            folders: FolderOpening = FolderOpening.UNAVAILABLE,
            localSubnet: () -> IPv4Subnet? = { null },
        ): SyncDependencies {
            val clock = SystemClock()
            val random = SystemRandomSource()
            val counters = HelloCounterSource(VaultCounterStore(slots), clock)
            return SyncDependencies(
                slots = slots, folders = folders, lan = lan(counters, random, clock), random = random, clock = clock,
                licenseKeys = LicenseKeys.production, localSubnet = localSubnet,
            )
        }
    }
}
