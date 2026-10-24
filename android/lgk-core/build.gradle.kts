plugins {
    alias(libs.plugins.kotlin.jvm)
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation(libs.bouncycastle)
    testImplementation(platform(libs.junit.bom))
    testImplementation(kotlin("test"))
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

tasks.test {
    useJUnitPlatform()
    systemProperty("lgk.repoRoot", rootDir.parentFile.absolutePath)
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = false
    }
}
