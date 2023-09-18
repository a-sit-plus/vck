import java.io.FileInputStream
import java.util.*

plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"

private val versions = Properties().apply {
    kotlin.runCatching { load(FileInputStream(rootProject.file("gradle-conventions-plugin/src/main/resources/versions.properties"))) }
}

dependencies {
    api("at.asitplus.gradle:conventions")
}

repositories {
    maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
    mavenCentral()
    gradlePluginPortal()
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
