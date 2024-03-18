import java.io.FileInputStream
import java.util.*

plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"

dependencies {
    api("at.asitplus.gradle:k2")
}

repositories {
    maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
    mavenCentral()
    gradlePluginPortal()
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
