package app.localgatekeys.android.unlock

import app.localgatekeys.android.vault.SecretSlots
import app.localgatekeys.core.primitives.RandomSource
import app.localgatekeys.core.primitives.UnixClock
import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot
import java.io.File
import java.nio.file.Files
import kotlinx.coroutines.CompletableDeferred

/** A clock tests move by hand. */
class TestClock(@Volatile override var now: Long) : UnixClock

/** Collects timers; [advance] fires the due ones in order (cancelled ones never). Port of the Swift ManualScheduler. */
class ManualScheduler(private val clock: TestClock) : LockScheduler {
    class Timer(val due: Long, val action: () -> Unit) : LockTimer {
        var cancelled = false
        override fun cancel() { cancelled = true }
    }

    val timers = mutableListOf<Timer>()

    override fun schedule(afterSeconds: Long, action: () -> Unit): LockTimer =
        Timer(clock.now + afterSeconds, action).also { timers.add(it) }

    fun advance(by: Long) {
        val target = clock.now + by
        while (true) {
            val next = timers.filter { !it.cancelled && it.due <= target }.minByOrNull { it.due } ?: break
            clock.now = next.due
            next.cancelled = true
            next.action()
        }
        clock.now = target
    }

    val pending: Int get() = timers.count { !it.cancelled }
}

/** An in-memory [ItemStore] (commit checks the base revision like LocalStore). */
class MemoryItemStore(var snapshot: StoreSnapshot = StoreSnapshot()) : ItemStore {
    override fun load(): StoreSnapshot = snapshot
    override fun commit(change: StoreChange) {
        check(change.baseRevision == snapshot.revision) { "stale" }
        snapshot = StoreSnapshot(change.records, change.meta, change.sync, snapshot.revision + 1)
    }
}

class CountingRandom : RandomSource {
    private var n = 0
    override fun bytes(count: Int): ByteArray = ByteArray(count) { (n++ and 0xff).toByte() }
}

fun tempDir(prefix: String): File = Files.createTempDirectory(prefix).toFile()

/** Port of the Swift FakeUnlocker: returns a vault, or throws [error] (default [Denied]) when [succeed] is false. */
class FakeUnlocker : Unlocker {
    class Denied : Exception("denied")

    var succeed = true
    var error: Exception? = null
    /** Runs while the unlock is "in flight" (after the prompt, before it returns). */
    var duringUnlock: (() -> Unit)? = null
    /** When set, each unlock waits for the next gate in this queue (tests interleave unlocks and locks). */
    val gates = ArrayDeque<CompletableDeferred<Unit>>()
    var unlockCalls = 0
    var lockCalls = 0
    val opened = mutableListOf<UnlockedVault>()
    val discarded = mutableListOf<UnlockedVault>()
    val store = MemoryItemStore()
    private val slotsFile = File(tempDir("fake-unlocker"), "secrets.bin")

    override suspend fun unlock(reason: String): UnlockedVault {
        unlockCalls++
        gates.removeFirstOrNull()?.await()
        duringUnlock?.invoke()
        if (!succeed) throw error ?: Denied()
        val key = ByteArray(32) { 7 }
        return UnlockedVault(store, SecretSlots(slotsFile, key, CountingRandom()), key).also { opened += it }
    }

    override fun lock() { lockCalls++ }

    override fun discard(vault: UnlockedVault) { discarded += vault }
}

/** Port of the Swift FakeEraser. */
class FakeEraser : VaultErasing {
    var failuresLeft = 0
    var calls = 0
    override suspend fun erase() {
        calls++
        if (failuresLeft > 0) {
            failuresLeft--
            throw VaultEraseFailure(listOf("local-key"))
        }
    }
}
