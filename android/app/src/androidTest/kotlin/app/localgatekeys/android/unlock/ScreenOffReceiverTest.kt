package app.localgatekeys.android.unlock

import android.os.ParcelFileDescriptor
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** Ruling 21: the real `ACTION_SCREEN_OFF` receiver reports the screen turning off, and nothing after [stop]. */
class ScreenOffReceiverTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val watcher = ScreenOffReceiver(instrumentation.targetContext)

    private fun shell(cmd: String) {
        val pfd: ParcelFileDescriptor = instrumentation.uiAutomation.executeShellCommand(cmd)
        ParcelFileDescriptor.AutoCloseInputStream(pfd).use { it.readBytes() }
    }

    private fun wake() {
        shell("input keyevent KEYCODE_WAKEUP")
        shell("wm dismiss-keyguard")
        Thread.sleep(500)
    }

    @After fun tearDown() {
        instrumentation.runOnMainSync { watcher.stop() }
        wake()
    }

    @Test fun screen_off_is_reported_while_watching_only() {
        wake()
        val calls = AtomicInteger()
        val first = CountDownLatch(1)
        instrumentation.runOnMainSync {
            watcher.start {
                calls.incrementAndGet()
                first.countDown()
            }
        }
        shell("input keyevent KEYCODE_SLEEP")
        assertTrue("screen-off not reported", first.await(10, TimeUnit.SECONDS))
        assertEquals(1, calls.get())

        wake()
        instrumentation.runOnMainSync { watcher.stop() }
        shell("input keyevent KEYCODE_SLEEP")
        Thread.sleep(2000)
        assertEquals(1, calls.get()) // stopped: nothing more
    }
}
