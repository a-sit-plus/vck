import org.tomlj.Toml
import org.tomlj.TomlParseResult
import java.io.FileInputStream
import java.util.*

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

if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("signum")
} else logger.lifecycle("Excluding Signum from this build")

rootProject.name = "vc-k"
include(":dif-data-classes")
include(":openid-data-classes")
include(":rqes-data-classes")
include(":vck")
include(":vck-openid")
include(":vck-rqes")
include(":vck-openid-ktor")


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

    versionCatalogs {
        create("signum") {
            from("at.asitplus.signum:indispensable-versionCatalog:${versionOf("signum")}")
        }
    }
}
