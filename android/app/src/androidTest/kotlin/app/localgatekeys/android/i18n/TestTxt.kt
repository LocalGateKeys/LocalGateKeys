package app.localgatekeys.android.i18n

import androidx.test.platform.app.InstrumentationRegistry

/** The app's own resources (English on the test device), for assertions on visible text. */
fun appTxt(): Txt = AndroidTxt(InstrumentationRegistry.getInstrumentation().targetContext.resources)
