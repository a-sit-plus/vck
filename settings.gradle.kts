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
include(":etsi-data-classes")
include(":vck")
include(":vck-openid")
include(":vck-openid-ktor")
include(":rfc3986-uri-syntax")
include(":sd-jwt-type-metadata")
include(":vck-longfellow")


val signumFile = file("../signum/build.gradle.kts")
if (signumFile.exists()) {
    logger.warn("Detected signum in ${signumFile.absolutePath}.")
    logger.warn("Including signum as composite build.")
    includeBuild("../signum")
}

dependencyResolutionManagement {
    repositories {
        mavenLocal()
        mavenCentral()
    }
}
