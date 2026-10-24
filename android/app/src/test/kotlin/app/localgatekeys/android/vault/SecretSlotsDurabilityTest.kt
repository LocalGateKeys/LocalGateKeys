package app.localgatekeys.android.vault

import app.localgatekeys.core.primitives.RandomSource
import java.io.File
import java.io.IOException
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.fail
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** Fix round 1: directory fsync, cross-instance serialisation, slot-key pinning, key-length checks. */
class SecretSlotsDurabilityTest {
    @get:Rule val tmp = TemporaryFolder()

    private class Rnd(private val seed: Int) : RandomSource {
        private var n = 0
        @Synchronized override fun bytes(count: Int): ByteArray {
            n++
            return ByteArray(count) { (seed * 31 + n + it).toByte() }
        }
    }

    private val key = ByteArray(32) { (it + 1).toByte() }
    private fun file() = File(tmp.root, "secrets.bin")
    private fun slots(seed: Int = 1) = SecretSlots(file(), key, Rnd(seed))

    @Test fun slot_key_strings_are_pinned() {
        assertEquals(
            mapOf(
                Slot.PAIRED_PEER to "paired-peer", Slot.INSTALL_ID to "install-id", Slot.HELLO_COUNTER to "hello-counter",
                Slot.PEER_COUNTERS to "peer-counters", Slot.FOLDER_URI to "folder-uri",
            ),
            Slot.entries.associateWith { it.key },
        )
        assertEquals(5, Slot.entries.size)
    }

    @Test fun all_slots_round_trip_together() {
        val s = slots()
        for ((i, slot) in Slot.entries.withIndex()) s.write(slot, byteArrayOf(i.toByte(), 9))
        val again = slots(2)
        for ((i, slot) in Slot.entries.withIndex()) assertArrayEquals(slot.name, byteArrayOf(i.toByte(), 9), again.read(slot))
    }

    @Test fun stored_non_hex_install_id_is_returned_as_is() {
        val s = slots()
        s.write(Slot.INSTALL_ID, "abc".toByteArray())
        assertEquals("abc", s.installId())
    }

    @Test fun directory_is_fsynced_after_the_rename_and_a_failure_is_reported() {
        val events = mutableListOf<String>()
        val s = SecretSlots(
            file(), key, Rnd(1),
            { events += "before:" + file().exists() },
            { d -> events += "dirsync:" + (d.canonicalPath == tmp.root.canonicalPath) + ":" + file().exists() },
        )
        s.write(Slot.FOLDER_URI, byteArrayOf(1))
        assertEquals(listOf("before:false", "dirsync:true:true"), events)
        val bad = SecretSlots(file(), key, Rnd(3), {}, { throw IOException("fsync failed") })
        try {
            bad.write(Slot.FOLDER_URI, byteArrayOf(2))
            fail()
        } catch (e: IOException) {
            assertEquals("fsync failed", e.message)
        }
        assertEquals(emptyList<String>(), tmp.root.list()!!.filter { it.endsWith(".tmp") })
    }

    @Test fun two_instances_on_one_file_lose_no_update() {
        val a = SecretSlots(file(), key, Rnd(1))
        val b = SecretSlots(File(tmp.root, "./secrets.bin"), key, Rnd(2))
        val ca = VaultCounterStore(a)
        val cb = VaultCounterStore(b)
        val n = 25
        val errors = java.util.concurrent.CopyOnWriteArrayList<Throwable>()
        val threads = listOf(
            Thread { runCatching { for (i in 1..n) ca.setLastAcceptedCounter(i.toLong(), "a$i") }.onFailure { errors += it } },
            Thread { runCatching { for (i in 1..n) cb.setLastAcceptedCounter(i.toLong(), "b$i") }.onFailure { errors += it } },
            Thread { runCatching { for (i in 1..n) a.write(Slot.FOLDER_URI, byteArrayOf(i.toByte())) }.onFailure { errors += it } },
            Thread { runCatching { for (i in 1..n) b.write(Slot.HELLO_COUNTER, ByteArray(8) { i.toByte() }) }.onFailure { errors += it } },
        )
        threads.forEach { it.start() }
        threads.forEach { it.join() }
        assertEquals(emptyList<Throwable>(), errors.toList())
        val check = VaultCounterStore(slots(9))
        for (i in 1..n) {
            assertEquals(i.toLong(), check.lastAcceptedCounter("a$i"))
            assertEquals(i.toLong(), check.lastAcceptedCounter("b$i"))
        }
        assertArrayEquals(byteArrayOf(n.toByte()), slots(9).read(Slot.FOLDER_URI))
        assertArrayEquals(ByteArray(8) { n.toByte() }, slots(9).read(Slot.HELLO_COUNTER))
    }

    @Test fun wrap_and_unwrap_check_the_local_key_length() {
        val v = FakeVaultKey().also { it.create() }
        try {
            v.wrap(ByteArray(31), v.cipherForWrap())
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
        val c = v.cipherForWrap()
        val wrapped = c.iv + c.doFinal(ByteArray(16))
        try {
            v.unwrap(wrapped, v.cipherForUnwrap(wrapped))
            fail()
        } catch (e: VaultKeyException) {
            assertEquals(VaultKeyException.Kind.FAILED, e.kind)
        }
    }
}
