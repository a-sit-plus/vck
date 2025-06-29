import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import java.io.FileInputStream
import java.util.*

plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"

private val versions = Properties().apply {
    kotlin.runCatching {
        FileInputStream(project.file("src/main/resources/vcLibVersions.properties")).use { load(it) }
    }
}

val kotlinVersion = versions["kotlin"]
val agp = versions["agp"]

dependencies {
    api("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
    api("org.jetbrains.kotlin:kotlin-serialization:$kotlinVersion")
    api("io.kotest:kotest-framework-multiplatform-plugin-gradle:6.0.0.M1")
    api("at.asitplus.gradle:k2")
    api("com.squareup:kotlinpoet:1.16.0")
    api("com.android.library:com.android.library.gradle.plugin:$agp")
    api("de.mannodermaus.gradle.plugins:android-junit5:1.11.0.0")

}

repositories {
    maven {
        url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
        name = "aspConventions"
    } //KOTEST snapshot
    mavenCentral()
    google()
    gradlePluginPortal()
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}

tasks.withType<KotlinCompile>().configureEach {
    kotlinOptions {
        freeCompilerArgs = freeCompilerArgs + "-Xcontext-receivers"
    }
}

kotlin {
    jvmToolchain(17)
}