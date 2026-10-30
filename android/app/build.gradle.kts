plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// AGP 9 has built-in Kotlin support: no org.jetbrains.kotlin.android plugin is applied.
kotlin {
    jvmToolchain(17)
}

android {
    namespace = "app.localgatekeys.android"
    compileSdk = 37

    defaultConfig {
        applicationId = "app.localgatekeys.android"
        minSdk = 29
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            // Pseudo-locales (en-XA, ar-XB) for finding clipped or hard-coded text.
            isPseudoLocalesEnabled = true
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
        unitTests.all { it.systemProperty("lgk.repoRoot", rootDir.parentFile.absolutePath) }
    }
}

val copyVectors = tasks.register<Copy>("copyVectors") {
    into(layout.buildDirectory.dir("generated/vectors/vectors"))
    from(rootDir.parentFile.resolve("tests/vectors/sync")) {
        include("expected.json", "keyring_epoch1.json", "keyring_epoch2.json", "lan/qr_payload.txt")
        into("sync")
    }
    // The desktop password strength vectors (Ruling 26): the estimator also runs on the device's ICU character data.
    from(rootDir.parentFile.resolve("tests/vectors/password_strength")) {
        include("vectors.json")
        into("password_strength")
    }
}

// Part C: the desktop's public suffix list, byte for byte, for the autofill and passkey matching.
val copyAppAssets = tasks.register<Copy>("copyAppAssets") {
    into(layout.buildDirectory.dir("generated/appAssets"))
    from(rootDir.parentFile.resolve("src/localvault/assets")) { include("public_suffix_list.dat") }
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addStaticSourceDirectory(layout.buildDirectory.dir("generated/appAssets").get().asFile.absolutePath)
        variant.androidTest?.sources?.assets?.addStaticSourceDirectory(
            layout.buildDirectory.dir("generated/vectors").get().asFile.absolutePath,
        )
    }
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("AndroidTestAssets") }.configureEach {
    dependsOn(copyVectors)
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }.configureEach {
    dependsOn(copyAppAssets)
}

dependencies {
    implementation(project(":lgk-core"))
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.graphics)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.core)
    implementation(libs.androidx.compose.material.icons.extended)
    implementation(libs.androidx.activity.compose)
    // Per-app language: AppCompatDelegate.setApplicationLocales (stored for API < 33 by AppLocalesMetadataHolderService).
    implementation(libs.androidx.appcompat)
    implementation(libs.argon2kt)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.lifecycle.process)
    implementation(libs.androidx.lifecycle.runtime.compose)
    // QR scanning: CameraX preview + ZXing (no Google Play Services, no ML Kit).
    implementation(libs.androidx.camera.core)
    implementation(libs.androidx.camera.camera2)
    implementation(libs.androidx.camera.lifecycle)
    implementation(libs.androidx.camera.view)
    implementation(libs.zxing.core)
    // Part C: the passkey and password provider (CredentialProviderService entries and request/response JSON).
    implementation(libs.androidx.credentials)
    // Inline autofill suggestions in the keyboard (API 30+): the suggestion chip layout.
    implementation(libs.androidx.autofill)
    // Pro: the one-time product pro_unlimited through the Play Store app (the only Google Play dependency).
    implementation(libs.play.billing) {
        // Ruling 23: no Google telemetry uploader (datatransport/CCT, firebase-encoders with it) and none of the Play
        // services modules billing declares but never calls (location brings places-placereport). Basement stays.
        exclude(group = "com.google.android.datatransport")
        exclude(group = "com.google.firebase", module = "firebase-encoders")
        exclude(group = "com.google.firebase", module = "firebase-encoders-json")
        exclude(group = "com.google.firebase", module = "firebase-encoders-proto")
        exclude(group = "com.google.android.gms", module = "play-services-location")
        exclude(group = "com.google.android.gms", module = "play-services-places-placereport")
        exclude(group = "com.google.android.gms", module = "play-services-base")
        exclude(group = "com.google.android.gms", module = "play-services-tasks")
    }
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit4)

    androidTestImplementation(libs.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.androidx.test.uiautomator)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.compose.ui.test.junit4.accessibility)
}
