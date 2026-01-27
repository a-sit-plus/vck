plugins {
    id("com.google.devtools.ksp") version libs.versions.kotlin.get()+"-2.0.4"
    id("io.kotest") version libs.versions.kotest
    id("at.asitplus.gradle.vclib-conventions") version libs.versions.kotlin
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

