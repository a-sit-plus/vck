import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.tomlj.Toml
import org.tomlj.TomlParseResult

plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"


buildscript {
    dependencies {
        classpath("org.tomlj:tomlj:1.1.1")
    }
}


val versionCatalog: TomlParseResult? by lazy {
    runCatching {
        Toml.parse(
            project.rootProject.layout.projectDirectory.dir("..").dir("gradle")
                .file("libs.versions.toml").asFile.inputStream()
        )
    }.getOrNull()
}

/**
 * Gets the version for the dependencies managed by shorthands. Can be overridden by `gradle/libs.versions.toml`
 */
internal fun versionOf(dependency: String) =
    versionCatalog?.getTable("versions")?.getString(dependency) as String


val agp = versionOf("agp")
val kotlinVer = versionOf("kotlin")

dependencies {
    api("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVer")
    api("org.jetbrains.kotlin:kotlin-serialization:$kotlinVer")
    api("at.asitplus.gradle:k2:+")
    api("com.squareup:kotlinpoet:1.16.0")
    api("com.android.library:com.android.library.gradle.plugin:$agp")
    api("de.mannodermaus.gradle.plugins:android-junit5:1.11.0.0")
    api("org.tomlj:tomlj:1.1.1")

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