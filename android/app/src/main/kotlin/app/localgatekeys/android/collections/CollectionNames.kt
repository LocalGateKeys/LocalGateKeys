package app.localgatekeys.android.collections

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.ui.res.stringResource
import app.localgatekeys.android.R

/**
 * Starter collections keep their English names in the vault (every platform adds and matches them by name), so they
 * are translated only on screen; any other name is shown as typed (LGKCore `CollectionCatalog.displayName`).
 */
object CollectionNames {
    @StringRes
    fun starterRes(name: String): Int? = when (name) {
        "Personal" -> R.string.collection_starter_personal
        "Work" -> R.string.collection_starter_work
        "Travel" -> R.string.collection_starter_travel
        "Emergency" -> R.string.collection_starter_emergency
        else -> null
    }
}

/** The name to show for a collection named [name]. */
@Composable
fun collectionDisplayName(name: String): String = CollectionNames.starterRes(name)?.let { stringResource(it) } ?: name
