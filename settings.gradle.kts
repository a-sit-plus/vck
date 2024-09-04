import org.apache.tools.ant.taskdefs.condition.Os
import java.io.FileInputStream
import java.util.*

pluginManagement {
    includeBuild("conventions-vclib")
    repositories {

        maven("https://s01.oss.sonatype.org/content/repositories/snapshots")
        google()
        gradlePluginPortal()
        mavenCentral()
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
include(":vck")
include(":vck-aries")
include(":vck-openid")

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
        maven {
            url = uri("file:${rootDir.absolutePath}/signum/repo")
            name = "signum"
        }
    }

    if (!File("${rootDir.absolutePath}/signum/repo/at/asitplus/signum/indispensable-versionCatalog/3.7.0-SNAPSHOT/maven-metadata.xml").exists()) {
        logger.lifecycle("building Signum for version catalogs. this will take a long time!")
        kotlin.runCatching {
            file("local.properties").also { src ->
                src.copyTo(
                    file("./signum/local.properties"),
                    overwrite = true
                )
            }
        }
        exec {
            workingDir = File("${rootDir.absolutePath}/signum")

            commandLine(
                if (!Os.isFamily(Os.FAMILY_WINDOWS)) "./gradlew" else "./gradlew.bat",
                "publishAllPublicationsToLocalRepository"
            )
        }
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