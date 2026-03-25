import org.tomlj.Toml
import org.tomlj.TomlParseResult
import java.io.FileInputStream

pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}


rootProject.name = "vc-k"
include(":dif-data-classes")
include(":openid-data-classes")
include(":csc-data-classes")
include(":vck")
include(":vck-openid")
include(":vck-openid-ktor")


val signumFile = file("../signum/build.gradle.kts")
if (signumFile.exists()) {
    logger.warn("Detected signum in ${signumFile.absolutePath}.")
    logger.warn("Including signum as composite build.")
    includeBuild("../signum")
}

buildscript {
    repositories {
        mavenCentral()
    }
    dependencies {
        classpath("org.tomlj:tomlj:1.1.1")
    }
}


val versionCatalogSource: TomlParseResult by lazy {

        Toml.parse(FileInputStream(rootProject.projectDir.absolutePath + ("/gradle/libs.versions.toml")))

}

/**
 * Gets the version for the dependencies managed by shorthands. Can be overridden by `gradle/libs.versions.toml`
 */
internal fun versionOf(dependency: String) =
    versionCatalogSource.getTable("versions")?.getString(dependency) as String




dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
    }
}
