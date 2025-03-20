import org.gradle.kotlin.dsl.maven
import java.io.FileInputStream
import java.util.*

pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        google()
        gradlePluginPortal()
        mavenCentral()
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        maven {
            url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
            name = "aspConventions"
        }
    }
}

if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("signum") {
        dependencySubstitution {
            substitute(module("at.asitplus.signum:indispensable")).using(project(":indispensable"))
            substitute(module("at.asitplus.signum:indispensable-josef")).using(project(":indispensable-josef"))
            substitute(module("at.asitplus.signum:indispensable-cosef")).using(project(":indispensable-cosef"))
            substitute(module("at.asitplus.signum:supreme")).using(project(":supreme"))
        }
    }
} else logger.lifecycle("Excluding Signum from this build")

rootProject.name = "vc-k"
include(":dif-data-classes")
include(":openid-data-classes")
include(":rqes-data-classes")
include(":vck")
include(":vck-openid")
include(":vck-rqes")
include(":vck-openid-ktor")

dependencyResolutionManagement {
    repositories {
        maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //Signum snapshot
        mavenLocal()
        mavenCentral()
    }

    versionCatalogs {
        val versions = Properties().apply {
            kotlin.runCatching {
                FileInputStream(rootProject.projectDir.absolutePath + ("/conventions-vclib/src/main/resources/vcLibVersions.properties")).use {
                    load(it)
                }
            }
        }

        fun versionOf(dependency: String) = versions[dependency] as String

        create("signum") {
            from("at.asitplus.signum:indispensable-versionCatalog:${versionOf("signum")}")
        }
    }
}
