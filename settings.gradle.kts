pluginManagement {
    includeBuild("conventions-vclib")
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