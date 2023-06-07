plugins {
    `kotlin-dsl`
}
group = "at.asitplus.gradle"

dependencies {
    api("at.asitplus.gradle:conventions:1.8.0")
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
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
    // Or provide your implemented plugins
}