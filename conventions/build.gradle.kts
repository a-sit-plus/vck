plugins {
    `kotlin-dsl`
}

group = "at.asitplus.gradle"
version="1.8.0"

dependencies {
    api("org.jetbrains.kotlin:kotlin-gradle-plugin:$version")
    api("org.jetbrains.kotlin:kotlin-serialization:$version")
    api("io.github.gradle-nexus:publish-plugin:1.3.0")
    api("io.kotest:kotest-framework-multiplatform-plugin-gradle:5.5.4")
    api("org.jetbrains.dokka:dokka-gradle-plugin:1.8.10")
}

repositories {
    mavenCentral()
    gradlePluginPortal()
}
kotlin {
    jvmToolchain {
        (this as JavaToolchainSpec).languageVersion.set(JavaLanguageVersion.of(11))
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