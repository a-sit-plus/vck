pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")
