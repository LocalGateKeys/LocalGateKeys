package app.localgatekeys.android.widget

import android.app.KeyguardManager
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager
import androidx.glance.appwidget.GlanceAppWidgetManager
import androidx.glance.appwidget.updateAll
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import app.localgatekeys.android.LgkApp
import app.localgatekeys.android.codes.PinnedCode
import app.localgatekeys.android.codes.PinnedCodes
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/**
 * Keeps the codes widget current. One per process ([LgkApp.codesWidget]); nothing here is stored.
 *
 * Refreshes: on every lock and unlock, after every store commit (edits and sync, which also prunes pins), after a pin
 * change, at each period boundary of a shown code and at the vault's lock deadline, and when the screen turns off, on
 * or is unlocked. Digits are shown only while the vault is open, before its auto-lock deadline, with the screen on and
 * the keyguard gone; otherwise the widget says "Unlock to show codes".
 *
 * Cadence (Android limits): the system's own widget updates are off (`updatePeriodMillis` 0). While codes are shown,
 * an in-process timer refreshes at the next period boundary (every 30 s for the usual codes); nothing runs while the
 * vault is locked, nothing is pinned, no widget is placed or the screen is off. A one-time WorkManager job at the
 * same boundary is the fallback when the process dies with codes on screen: it starts a new process, which has no
 * vault key, so the widget then shows the locked state. An alarm ([CodesWidgetAlarm]) backs the job up, since jobs
 * can wait for quota.
 */
class CodesWidgetUpdates(
    private val context: Context,
    private val codes: PinnedCodes,
    private val scope: CoroutineScope,
    /** The open vault's lock deadline (`AppLockModel.lockDeadline`); null while locked. */
    private val lockDeadline: () -> Long?,
    /** Auto-lock is "Immediately" (the locked widget then says how to see codes). */
    private val lockImmediately: () -> Boolean = { false },
    private val nowMillis: () -> Long = System::currentTimeMillis,
) {
    private val _state = MutableStateFlow<CodesWidgetState>(CodesWidgetState.Locked)
    val state: StateFlow<CodesWidgetState> = _state.asStateFlow()

    private val mutex = Mutex()
    private var tick: Job? = null
    private var screenReceiver: BroadcastReceiver? = null

    /** Refreshes soon; any thread. */
    fun request() {
        scope.launch { refresh() }
    }

    /** Computes the state and pushes it to every placed widget. */
    suspend fun refresh() {
        val next = prepare() ?: return
        CodesWidget().updateAll(context)
        schedule(next.delay)
    }

    /** For the widget's own first composition: computes [state] without pushing an update. */
    suspend fun prepareForWidget() {
        val next = prepare() ?: return
        schedule(next.delay)
    }

    private class Next(val delay: Long?)

    /** Null when no widget is placed (every timer is stopped then). */
    private suspend fun prepare(): Next? = mutex.withLock {
        val placed = try {
            GlanceAppWidgetManager(context).getGlanceIds(CodesWidget::class.java).isNotEmpty()
        } catch (e: Exception) {
            false
        }
        if (!placed) {
            withContext(Dispatchers.Main) { stopTimers(); watchScreen(false) }
            _state.value = CodesWidgetState.Locked
            return null
        }
        val visible = screenUsable()
        val deadline = lockDeadline()
        val now = nowMillis()
        val shown = if (visible && deadline != null && now / 1000 < deadline) {
            withContext(Dispatchers.IO) { codes.codes(now / 1000) }
        } else {
            // No store read: the pin list alone says Locked or Empty.
            codes.ids().map { PinnedCode(it, "", null, 0) }
        }
        val state = CodesWidgetState.of(shown, visible = true, lockImmediately = lockImmediately())
        _state.value = state
        withContext(Dispatchers.Main) { watchScreen(shown.isNotEmpty()) }
        Next(
            when {
                state is CodesWidgetState.Codes -> codesShownDelay(CodesWidgetState.nextRefreshDelay(shown, deadline, now))
                // Hidden only by the screen: Android 14+ holds a cached app's USER_PRESENT until it is opened again,
                // so poll until the vault's own deadline instead of waiting for the broadcast.
                shown.isNotEmpty() && !visible -> screenLockedPollDelay(deadline, now)
                else -> null
            },
        )
    }

    private suspend fun schedule(delayMillis: Long?) = withContext(Dispatchers.Main) {
        if (delayMillis == null) {
            stopTimers()
            return@withContext
        }
        tick?.cancel()
        tick = scope.launch {
            delay(delayMillis)
            // Not cancellable: this refresh replaces the timer (and the job) that started it.
            withContext(NonCancellable) { refresh() }
        }
        try {
            WorkManager.getInstance(context).enqueueUniqueWork(
                WORK_NAME, ExistingWorkPolicy.REPLACE,
                OneTimeWorkRequestBuilder<CodesWidgetWorker>().setInitialDelay(delayMillis, TimeUnit.MILLISECONDS).build(),
            )
        } catch (e: Exception) {
            // WorkManager unavailable: the in-process timer still runs.
        }
        // Jobs can wait for quota (Android 10: 20 jobs in ten minutes); the alarm cannot.
        CodesWidgetAlarm.arm(context, delayMillis + ALARM_SLACK_MILLIS, nowMillis())
    }

    private fun stopTimers() {
        tick?.cancel(); tick = null
        try {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        } catch (e: Exception) {
            // not initialised
        }
        CodesWidgetAlarm.cancel(context)
    }

    /** The screen is on and past the keyguard (the lock screen never carries digits). */
    private fun screenUsable(): Boolean {
        val power = context.getSystemService(PowerManager::class.java)
        val keyguard = context.getSystemService(KeyguardManager::class.java)
        return power?.isInteractive == true && keyguard?.isKeyguardLocked != true
    }

    /** While pins exist: screen off hides the digits at once; screen on / unlock shows them again (vault still open). */
    private fun watchScreen(on: Boolean) {
        if (on == (screenReceiver != null)) return
        if (!on) {
            val r = screenReceiver ?: return
            screenReceiver = null
            try { context.unregisterReceiver(r) } catch (e: IllegalArgumentException) { }
            return
        }
        val r = object : BroadcastReceiver() {
            override fun onReceive(context: Context, intent: Intent) {
                request()
            }
        }
        val filter = IntentFilter().apply {
            addAction(Intent.ACTION_SCREEN_OFF)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_USER_PRESENT)
        }
        // Protected system broadcasts: they still arrive with RECEIVER_NOT_EXPORTED.
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(r, filter, Context.RECEIVER_NOT_EXPORTED) else context.registerReceiver(r, filter)
        screenReceiver = r
    }

    companion object {
        const val WORK_NAME = "codes-widget-refresh"

        /** The alarm fires a little after the in-process timer, which moves it on while the process lives. */
        const val ALARM_SLACK_MILLIS = 2_000L

        /** How often a widget hidden only by the screen lock checks whether the phone was unlocked. */
        const val SCREEN_LOCKED_POLL_MILLIS = 15_000L

        /**
         * The longest wait between refreshes while codes show. A killed process leaves only the WorkManager job, which
         * fired at the next code period (up to 30 s, plus the scheduler's own lag): the digits stayed up to ~60 s.
         */
        const val CODES_SHOWN_MAX_DELAY_MILLIS = 20_000L

        /** [delay] capped at [CODES_SHOWN_MAX_DELAY_MILLIS], so a dead process is noticed within 30 s. */
        fun codesShownDelay(delay: Long?): Long = minOf(delay ?: CODES_SHOWN_MAX_DELAY_MILLIS, CODES_SHOWN_MAX_DELAY_MILLIS)

        /**
         * The next check while the vault is open but the screen is off or locked: every [SCREEN_LOCKED_POLL_MILLIS],
         * never past the lock [deadline] (Unix seconds); null once the vault is locked or past its deadline.
         */
        fun screenLockedPollDelay(deadline: Long?, nowMillis: Long): Long? {
            if (deadline == null || deadline == Long.MAX_VALUE || nowMillis / 1000 >= deadline) {
                return if (deadline == Long.MAX_VALUE) SCREEN_LOCKED_POLL_MILLIS else null
            }
            return minOf(SCREEN_LOCKED_POLL_MILLIS, deadline * 1000 - nowMillis + 100)
        }
    }
}

/** The fallback refresh at a code's period boundary (see [CodesWidgetUpdates]). */
class CodesWidgetWorker(context: Context, params: WorkerParameters) : CoroutineWorker(context, params) {
    override suspend fun doWork(): Result {
        // Not cancellable: the refresh replaces this unique job with the next one.
        withContext(NonCancellable) { (applicationContext as? LgkApp)?.codesWidget?.refresh() }
        return Result.success()
    }
}
