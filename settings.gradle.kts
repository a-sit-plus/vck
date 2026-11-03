System.setProperty("KOTEST_NO_ASP_HELPER", "true")

pluginManagement {
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
    }
    includeBuild("conventions-vclib")
}
rootProject.name = "vclibrary"
include(":vclib")

