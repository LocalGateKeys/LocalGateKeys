plugins {
    alias(libs.plugins.android.application)
}

// Sub-plan 06: the Wear OS app that holds only the pinned-codes tile. It talks to the phone app over the Wearable Data
// Layer, which pairs apps by package name and signing key: the application id is the phone app's (the namespace
// differs). No INTERNET permission; nothing is backed up.
kotlin {
    jvmToolchain(17)
}

android {
    namespace = "app.localgatekeys.wear"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.localgatekeys.android"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "1.0.0"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }
}

dependencies {
    // The message format and its ordering rules, shared with the phone (WearCodes).
    implementation(project(":lgk-core"))
    implementation(libs.androidx.wear.tiles)
    implementation(libs.androidx.wear.protolayout)
    implementation(libs.androidx.concurrent.futures)
    implementation(libs.play.wearable)

    testImplementation(libs.junit4)
}
