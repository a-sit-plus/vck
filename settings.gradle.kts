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

if (System.getProperty("publishing.excludeIncludedBuilds") != "true") {
    includeBuild("kmp-crypto") {
        dependencySubstitution {
            substitute(module("at.asitplus.crypto:datatypes")).using(project(":datatypes"))
            substitute(module("at.asitplus.crypto:datatypes-jws")).using(project(":datatypes-jws"))
            substitute(module("at.asitplus.crypto:datatypes-cose")).using(project(":datatypes-cose"))
        }
    }
} else logger.lifecycle("Excluding KMP Crypto from this build")

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")

dependencyResolutionManagement {
    repositories.add(repositories.mavenCentral())
    versionCatalogs {
        val versions = Properties().apply {
            kotlin.runCatching {
                FileInputStream(rootProject.projectDir.absolutePath + ("/conventions-vclib/src/main/resources/vcLibVersions.properties")).use {
                    load(it)
                }
            }
        }

        fun versionOf(dependency: String) = versions[dependency] as String

        create("kmpCrypto") {
            from("at.asitplus.crypto:datatypes-versionCatalog:${versionOf("kmpCrypto")}")
        }
    }
}