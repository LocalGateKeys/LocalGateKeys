package app.localgatekeys.core.records

import app.localgatekeys.core.engine.Engine
import app.localgatekeys.core.engine.EngineException
import app.localgatekeys.core.engine.ItemState
import app.localgatekeys.core.engine.MergeOutcome
import app.localgatekeys.core.engine.VersionVector
import app.localgatekeys.core.json.CanonicalJson
import app.localgatekeys.core.json.Dialect
import app.localgatekeys.core.json.JsonException
import app.localgatekeys.core.json.JsonValue
import app.localgatekeys.core.primitives.Identifier

/**
 * Per-id sync metadata (desktop `payload["sync_meta"]["items"][id]`): what this device last published.
 *
 * The phone stores each record as its synced wrapper (`records`: id -> wrapper JSON). A record the phone
 * does not edit is kept exactly as received, so its digest matches its meta and it is republished
 * byte for byte with an unchanged vector.
 */
data class SyncMeta(
    /** sha256 hex of the canonical wrapper; null for a tombstone. */
    val digest: String?,
    /** The same without `record.updated_at` and the wrapper rank; null for a tombstone. */
    val body: String?,
    /** The published `record.updated_at` (when it is an int). */
    val updatedAt: Long?,
    val vv: Map<String, Long>,
    val deleted: Boolean,
    val deletedAt: Long?,
) {
    data class LocalViewResult(
        val states: Map<String, ItemState>,
        val meta: Map<String, SyncMeta>,
        /** Stored records that cannot be published (id -> reason); their meta is untouched. */
        val skipped: Map<String, String>,
    )

    data class ApplyResult(
        val records: Map<String, JsonValue>,
        val meta: Map<String, SyncMeta>,
        val applied: Int,
        val deleted: Int,
        val conflicts: Int,
        /** Licence bundles received in this apply that verified (stored or already known). */
        val licenses: List<JsonValue>,
    )

    companion object {
        const val TOMBSTONE_MAX_AGE_DAYS: Long = 365
        const val MAX_SYNC_LICENSES = 16
        internal const val MAX_RECORDS = 20_000

        // MARK: digests

        private fun hex(v: JsonValue): String = Engine.sha256Hex(v)

        /** sha256 hex of the canonical JSON of a wrapper (desktop `wrapper_digest`). */
        fun digest(wrapper: JsonValue): String = hex(wrapper)

        /** Digest of `{"ns", "record" minus updated_at}` (desktop `_body_digest`). */
        fun bodyDigest(wrapper: JsonValue): String {
            val w = (wrapper as? JsonValue.Obj)?.fields
            val r = (w?.get("record") as? JsonValue.Obj)?.fields ?: throw RecordException(null, null, "not a wrapper")
            return hex(JsonValue.Obj(mapOf("ns" to (w["ns"] ?: JsonValue.Null), "record" to JsonValue.Obj(r - "updated_at"))))
        }

        fun live(wrapper: JsonValue, vv: Map<String, Long>): SyncMeta {
            val r = ((wrapper as? JsonValue.Obj)?.fields?.get("record") as? JsonValue.Obj)?.fields
            val stamp = (r?.get("updated_at") as? JsonValue.Int)?.v
            return SyncMeta(digest(wrapper), bodyDigest(wrapper), stamp, vv, false, null)
        }

        fun tomb(vv: Map<String, Long>, deletedAt: Long): SyncMeta = SyncMeta(null, null, null, vv, true, deletedAt)

        /** Drops tombstones deleted more than 365 days before [now]. */
        fun prune(meta: Map<String, SyncMeta>, now: Long): Map<String, SyncMeta> {
            val cutoff = now - TOMBSTONE_MAX_AGE_DAYS * 86400
            return meta.filterValues { !(it.deleted && (it.deletedAt ?: cutoff) < cutoff) }
        }

        private fun checkCall(device: String, now: Long) {
            if (!Identifier.isValid(device)) throw RecordException(null, null, "Sync device id is malformed")
            if (now < 0 || now > VersionVector.MAX_COUNTER) throw RecordException(null, null, "Sync clock value is malformed")
        }

        /** `LocalViewResult.skipped` reason of a record whose stored vector cannot be bumped (audit M-6). */
        const val COUNTER_OVERFLOW = "version counter overflow"

        /** `bump(vv, device)`, or null when this device's counter would overflow (desktop `_bumped`). */
        private fun bumped(vv: Map<String, Long>, device: String): Map<String, Long>? =
            if ((vv[device] ?: 0L) >= VersionVector.MAX_COUNTER) null else VersionVector.bump(vv, device)

        private fun nsName(wrapper: JsonValue): String? = ((wrapper as? JsonValue.Obj)?.fields?.get("ns") as? JsonValue.Str)?.v

        // MARK: local view

        /**
         * Engine states for every stored record and tombstone (desktop `local_view`), plus the updated meta.
         *
         * A record whose digest differs from its meta (or that has none) is a local edit: its vector is
         * bumped once for [device]. An id in meta that is no longer stored becomes a tombstone at [now]
         * with a bumped vector; licence ids never do (a licence no longer stored just goes quiet).
         */
        fun localView(records: Map<String, JsonValue>, meta: Map<String, SyncMeta>, device: String, now: Long): LocalViewResult {
            checkCall(device, now)
            val metaOut = LinkedHashMap(prune(meta, now))
            val states = LinkedHashMap<String, ItemState>()
            val skipped = LinkedHashMap<String, String>()
            try {
                for ((id, wrapper) in records) {
                    val isLicense = nsName(wrapper) == Namespace.LICENSE.wire
                    if (!Identifier.isValid(id) || Wrapper.isLicenseId(id) != isLicense) {
                        skipped[id] = "invalid-id"
                        continue
                    }
                    var m = metaOut[id]
                    val d = try {
                        digest(wrapper)
                    } catch (e: JsonException) {
                        skipped[id] = "unencodable"
                        continue
                    }
                    if (m == null || m.deleted || m.digest != d) {
                        // A vector stored before the plausibility rule: skip only this record.
                        val vv = bumped(m?.vv ?: emptyMap(), device)
                        if (vv == null) {
                            skipped[id] = COUNTER_OVERFLOW
                            continue
                        }
                        m = live(wrapper, vv)
                        metaOut[id] = m
                    }
                    states[id] = ItemState(id, m.vv, false, null, wrapper)
                }
                for ((id, m) in metaOut.entries.toList()) {
                    if (records.containsKey(id)) continue
                    if (Wrapper.isLicenseId(id) || !Identifier.isValid(id)) continue
                    var t = m
                    if (!m.deleted) {
                        // The delete cannot be recorded without an overflow: publish nothing for it.
                        t = tomb(bumped(m.vv, device) ?: continue, now)
                        metaOut[id] = t
                    }
                    states[id] = ItemState(id, t.vv, true, t.deletedAt, null)
                }
            } catch (e: EngineException) {
                throw RecordException(null, null, "Vault content cannot be synced: ${e.message}")
            }
            if (metaOut.size > MAX_RECORDS) throw RecordException(null, null, "Sync metadata exceeds its bound")
            return LocalViewResult(states, metaOut, skipped)
        }

        // MARK: apply

        private inline fun <T> blame(id: String, body: () -> T): T {
            try {
                return body()
            } catch (e: RecordException) {
                if (e.reason != null) throw e
                throw RecordException("bad-remote", id, e.detail)
            } catch (e: Exception) {
                throw RecordException("bad-remote", id, "Merge outcome cannot be applied: ${e.message ?: e.toString()}")
            }
        }

        /**
         * Applies a merge outcome to the stored records (desktop `apply`); pure, so a throw leaves the caller's
         * store untouched. Remote records are stored exactly as received (never normalised); a conflict copy
         * gets the copy id and the `" (sync conflict)"` suffix. A remote tombstone's `deleted_at` is capped at
         * [now]; one older than 365 days is ignored. Licences are verified with [licenseKeys], only ever added,
         * and dropped without a word when this build knows no licence keys or as a conflict copy.
         * Throws [RecordException] `vault-changed` when a record changed since its meta was written, and
         * `bad-remote` / `update-needed` naming the first remote state that cannot be stored.
         */
        fun applyRemote(
            outcome: MergeOutcome,
            records: Map<String, JsonValue>,
            meta: Map<String, SyncMeta>,
            device: String,
            now: Long,
            licenseKeys: Map<String, ByteArray>,
        ): ApplyResult {
            checkCall(device, now)
            val all = outcome.upserts + outcome.deletes + outcome.copies
            val ids = all.map { it.itemId }
            if (ids.toSet().size != ids.size) throw RecordException(null, null, "Merge outcome names a record more than once")
            if ((outcome.upserts + outcome.copies).any { it.deleted } || !outcome.deletes.all { it.deleted }) {
                throw RecordException(null, null, "Merge outcome is malformed")
            }
            val cutoff = now - TOMBSTONE_MAX_AGE_DAYS * 86400
            var deletes = ArrayList<Pair<ItemState, Long>>()
            for (s in outcome.deletes) {
                val at = minOf(s.deletedAt ?: now, now)
                if (at >= cutoff) deletes.add(s to at)
            }
            val stale = HashSet(outcome.deletes.map { it.itemId })
            stale.removeAll(deletes.map { it.first.itemId }.toSet())
            val published = records.filter { Wrapper.isLicenseId(it.key) && nsName(it.value) == Namespace.LICENSE.wire }
            for ((s, _) in deletes) if (Wrapper.isLicenseId(s.itemId) && published[s.itemId] == null) stale.add(s.itemId)
            if (licenseKeys.isEmpty()) {
                for (s in outcome.upserts) if (Wrapper.isLicenseId(s.itemId)) stale.add(s.itemId)
            }
            for (s in outcome.copies) if (s.item?.let { nsName(it) } == Namespace.LICENSE.wire) stale.add(s.itemId)
            deletes = ArrayList(deletes.filter { it.first.itemId !in stale })
            val liveIds = ids.filter { it !in stale }

            val recs = LinkedHashMap(records)
            val metaOut = LinkedHashMap(meta)
            // Refuse to apply over a local change that the merged view did not include.
            for (id in liveIds) {
                if (Wrapper.isLicenseId(id)) continue
                val m = metaOut[id]
                val current = recs[id]
                val fresh = if (m == null || m.deleted) current == null else current != null && digest(current) == m.digest
                if (!fresh) throw RecordException("vault-changed", id, "The vault changed since the sync view was taken; sync again")
            }
            var applied = 0
            var deleted = 0
            val received = ArrayList<JsonValue>()
            for ((s, at) in deletes) {
                if (Wrapper.isLicenseId(s.itemId)) {
                    // A licence is republished above the tombstone; an overflowing bump refuses only this state.
                    metaOut[s.itemId] = blame(s.itemId) { live(published.getValue(s.itemId), VersionVector.bump(s.vv, device)) }
                    continue
                }
                if (recs.remove(s.itemId) != null) deleted++
                metaOut[s.itemId] = tomb(s.vv, at)
            }
            for (s in outcome.upserts) {
                if (s.itemId in stale) continue
                blame(s.itemId) {
                    val (ns, record) = Wrapper.unwrap(s, false, licenseKeys)
                    if (ns == Namespace.LICENSE) {
                        val wrapper = Wrapper.make(Namespace.LICENSE, record)
                        val known = recs[s.itemId]
                        if (known != null) {
                            val k = (known as? JsonValue.Obj)?.fields
                            if (k == null || !CanonicalJson.encode(k["record"] ?: JsonValue.Null, Dialect.UTF8)
                                    .contentEquals(CanonicalJson.encode(record, Dialect.UTF8))
                            ) {
                                throw RecordException(null, null, "Licence state differs from the licence stored under that id")
                            }
                        } else {
                            if (recs.keys.count { Wrapper.isLicenseId(it) } >= MAX_SYNC_LICENSES) {
                                throw RecordException(null, null, "The vault holds as many synced licences as it keeps")
                            }
                            recs[s.itemId] = wrapper
                        }
                        metaOut[s.itemId] = live(wrapper, s.vv)
                        received.add(record)
                        return@blame
                    }
                    // The state was checked against Wrapper's rules, so its item is the wrapper itself:
                    // store it verbatim so it is republished byte for byte.
                    val stored = s.item!!
                    val current = recs[s.itemId]
                    if (current != null && nsName(current) != ns.wire) {
                        throw RecordException(null, null, "Record id is used by a different kind of record")
                    }
                    if ((current?.let { digest(it) }) != digest(stored)) applied++
                    recs[s.itemId] = stored
                    metaOut[s.itemId] = live(stored, s.vv)
                }
            }
            for (s in outcome.copies) {
                if (s.itemId in stale || recs[s.itemId] != null) continue
                blame(s.itemId) {
                    val (ns, record) = Wrapper.unwrap(s, true, licenseKeys)
                    val r = LinkedHashMap((record as? JsonValue.Obj)?.fields ?: throw RecordException(null, null, "malformed copy"))
                    val field = if (ns == Namespace.ENTRY) "label" else "title"
                    val t = (r[field] as? JsonValue.Str)?.v
                    if (t != null) r[field] = JsonValue.Str(ConflictSuffix.apply(t, ConflictSuffix.LIMIT))
                    val stored = Wrapper.make(ns, JsonValue.Obj(r))
                    recs[s.itemId] = stored
                    applied++
                    metaOut[s.itemId] = live(stored, s.vv)
                }
            }
            if (recs.size > MAX_RECORDS) throw RecordException(null, null, "The vault would hold more records than sync supports")
            return ApplyResult(recs, metaOut, applied, deleted, outcome.conflicts.size, received)
        }
    }
}
