plugins {
    id("org.gradle.toolchains.foojay-resolver-convention") version "1.0.0"
}

rootProject.name = "vclib-conventions"

//we don't want to pollute the classpath with a shadowed conventions plugin
includeBuild("gradle-conventions-plugin")
