package app.localgatekeys.android.sync

import app.localgatekeys.core.sync.ItemStore
import app.localgatekeys.core.sync.StoreChange
import app.localgatekeys.core.sync.StoreSnapshot

/** A refused join/leave step; [reason] is a desktop `ERROR_COPY` / `ISSUE_COPY` key (Swift `SyncActionError`). */
class SyncActionException(val reason: String) : Exception(reason)

/** Closed when the vault locks: from then on no sync may read or commit (checked right before each commit). */
class SessionGate {
    @Volatile private var closed = false

    fun close() {
        closed = true
    }

    val isOpen: Boolean get() = !closed

    override fun toString(): String = "SessionGate(open=$isOpen)"
}

/** The coordinator's view of the store: reads and commits are refused (`locked`) once the vault has locked. */
class GatedStore(val base: ItemStore, val gate: SessionGate) : ItemStore {
    override fun load(): StoreSnapshot {
        if (!gate.isOpen) throw SyncActionException("locked")
        return base.load()
    }

    override fun commit(change: StoreChange) {
        if (!gate.isOpen) throw SyncActionException("locked")
        base.commit(change)
    }

    /** Never shows the store's content. */
    override fun toString(): String = "GatedStore(open=${gate.isOpen})"
}
