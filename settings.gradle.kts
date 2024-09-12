pluginManagement {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //Kotest snapshot for Kotlin 2.0.20 until new Kotest stable is released
        google()
        gradlePluginPortal()
        mavenCentral()
    }
    includeBuild("conventions-vclib")
}
rootProject.name = "vclibrary"
include(":vclib")

