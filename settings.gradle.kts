import java.io.FileInputStream
import java.util.*

pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}
/*
if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("signum") {
        dependencySubstitution {
            substitute(module("at.asitplus.signum:indispensable")).using(project(":indispensable"))
            substitute(module("at.asitplus.signum:indispensable-josef")).using(project(":indispensable-josef"))
            substitute(module("at.asitplus.signum:indispensable-cosef")).using(project(":indispensable-cosef"))
        }
    }
} else logger.lifecycle("Excluding Signum from this build")*/

rootProject.name = "vc-k"
include(":dif-data-classes")
include(":openid-data-classes")
include(":vck")
include(":vck-aries")
include(":vck-openid")

dependencyResolutionManagement {
    repositories.add(repositories.mavenCentral())
    repositories.add(repositories.mavenLocal())
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