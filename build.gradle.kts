plugins {
    kotlin("multiplatform") version libs.versions.kotlin apply false
    kotlin("plugin.serialization") version libs.versions.kotlin apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp apply false
    id("de.infix.testBalloon") version libs.versions.testballoon apply false
    alias(libs.plugins.asp)
    id("at.asitplus.gradle.vclib-conventions") apply false
}

val artifactVersion = extra["artifactVersion"] as String
group = "at.asitplus.wallet"
version = artifactVersion

