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
            substitute(module("at.asitplus.crypto:datatypes-jws")).using(
                project(
                    ":datatypes-jws"
                )
            )
            substitute(module("at.asitplus.crypto:datatypes-cose")).using(
                project(":datatypes-cose")
            )
        }
    }
} else logger.lifecycle("Excluding KMP Crypto from this build")

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")

includeBuild("kmp-crypto") {
    dependencySubstitution {
        substitute(module("at.asitplus.crypto:datatypes")).using(project(":datatypes"))
        substitute(module("at.asitplus.crypto:datatypes-jws")).using(project(":datatypes-jws"))
        substitute(module("at.asitplus.crypto:datatypes-cose")).using(project(":datatypes-cose"))
    }
}
