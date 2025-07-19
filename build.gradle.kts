plugins {
    id("io.kotest.multiplatform") version libs.versions.kotest
    id("at.asitplus.gradle.vclib-conventions")
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

