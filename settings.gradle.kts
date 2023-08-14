pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")
/*
includeBuild("kotlinx.serialization") {
    dependencySubstitution {
        listOf("", "-jvm", "-iosx64", "-iosarm64", "-iossimulatorarm64").forEach { target ->
            listOf("core", "json", "cbor", "properties").forEach { format ->
                substitute(module("org.jetbrains.kotlinx:kotlinx-serialization-$format$target"))
                    .using(project(":kotlinx-serialization-$format"))
            }
        }
    }
}*/