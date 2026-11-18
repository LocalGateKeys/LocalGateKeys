package app.localgatekeys.android.pro

import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.emptyFlow
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.file.Files

class DebugProOverrideTest {
    private object FreeStore : ProPurchasing {
        override suspend fun isEntitled() = false
        override suspend fun offer(): ProOffer = throw UnsupportedOperationException()
        override suspend fun purchase(): PurchaseOutcome = throw UnsupportedOperationException()
        override suspend fun restore() = false
        override suspend fun purchaseToken(): String? = null
        override fun entitlementChanges(): Flow<Unit> = emptyFlow()
    }

    @Test
    fun releaseNeverWraps() {
        val dir = Files.createTempDirectory("lgk").toFile()
        assertSame(FreeStore, DebugProOverride.wrapIfDebug(false, FreeStore, dir))
    }

    @Test
    fun debugFollowsMarkerFile() = runBlocking {
        val dir = Files.createTempDirectory("lgk").toFile()
        val p = DebugProOverride.wrapIfDebug(true, FreeStore, dir)
        assertFalse(p.isEntitled())
        java.io.File(dir, DebugProOverride.MARKER).writeText("")
        assertTrue(p.isEntitled())
        assertTrue(p.restore())
    }
}
