package app.localgatekeys.android.ui.input

import android.view.inputmethod.EditorInfo
import androidx.compose.runtime.Composable
import androidx.compose.ui.ExperimentalComposeUiApi
import androidx.compose.ui.platform.InterceptPlatformTextInput
import androidx.compose.ui.platform.PlatformTextInputInterceptor
import androidx.compose.ui.platform.PlatformTextInputMethodRequest

/** Adds [EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING] to what a text field hands the keyboard. */
@OptIn(ExperimentalComposeUiApi::class)
internal val noPersonalisedLearning = PlatformTextInputInterceptor { request, next ->
    val wrapped = PlatformTextInputMethodRequest { outAttributes ->
        val connection = request.createInputConnection(outAttributes)
        outAttributes.imeOptions = outAttributes.imeOptions or EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
        connection
    }
    next.startInputMethod(wrapped)
}

/**
 * Ruling 15: every text field in [content] asks the keyboard not to learn from what is typed (no personalised
 * dictionary, no typing history). MainActivity wraps the whole app once, so search, the editor and every later field
 * get it.
 */
@OptIn(ExperimentalComposeUiApi::class)
@Composable
fun NoPersonalisedLearning(content: @Composable () -> Unit) {
    InterceptPlatformTextInput(noPersonalisedLearning, content)
}
