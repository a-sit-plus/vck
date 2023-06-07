import java.io.FileInputStream
import java.util.*

plugins {
    `kotlin-dsl`
}
private val versions = Properties().apply {
    kotlin.runCatching { load(FileInputStream(rootProject.file("src/main/resources/versions.properties"))) }
}
group = "at.asitplus.gradle"
version = versions["kotlin"]

val dokka = versions["dokka"]
val nexus = versions["nexus"]
val kotest = versions["kotest"]
val jvmTarget = versions["jvmTarget"] as String

dependencies {
    api("org.jetbrains.kotlin:kotlin-gradle-plugin:$version")
    api("org.jetbrains.kotlin:kotlin-serialization:$version")
    api("io.kotest:kotest-framework-multiplatform-plugin-gradle:$kotest")
    api("io.github.gradle-nexus:publish-plugin:$nexus")
    api("org.jetbrains.dokka:dokka-gradle-plugin:$dokka")
}

repositories {
    mavenCentral()
    gradlePluginPortal()
}
kotlin {
    jvmToolchain {
        (this as JavaToolchainSpec).languageVersion.set(JavaLanguageVersion.of(jvmTarget))
    }
}

gradlePlugin {
    // Add fake plugin, if you don't have any
    plugins.register("asp-conventions") {
        id = "at.asitplus.gradle.conventions"
        implementationClass = "at.asitplus.gradle.AspConventions"
    }
    // Or provide your implemented plugins
}