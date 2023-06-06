plugins {
    `kotlin-dsl`
}
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:1.8.0")
    api("org.jetbrains.kotlin:kotlin-serialization:1.8.0")
    api("io.github.gradle-nexus:publish-plugin:1.3.0")
    api("io.kotest:kotest-framework-multiplatform-plugin-gradle:5.5.4")
    api("org.jetbrains.dokka:dokka-gradle-plugin:1.8.10")
}

repositories {
    mavenCentral()
    gradlePluginPortal()
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "11"
    }
}

gradlePlugin {
    // Add fake plugin, if you don't have any
    plugins.register("asp-conventions") {
        id = "at.asitplus.gradle.conventions"
        implementationClass = "AspConventions"
    }
    // Or provide your implemented plugins
}