pluginManagement {
    includeBuild("conventions-vclib")
}

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")

includeBuild("kotlinx.serialization"){
    dependencySubstitution {
        substitute(module("org.jetbrains.kotlinx:kotlinx-serialization-core")).using(project(":kotlinx-serialization-core"))
        substitute(module("org.jetbrains.kotlinx:kotlinx-serialization-cbor")).using(project(":kotlinx-serialization-cbor"))
        substitute(module("org.jetbrains.kotlinx:kotlinx-serialization-json")).using(project(":kotlinx-serialization-json"))
        substitute(module("org.jetbrains.kotlinx:kotlinx-serialization-properties")).using(project(":kotlinx-serialization-properties"))
    }
}