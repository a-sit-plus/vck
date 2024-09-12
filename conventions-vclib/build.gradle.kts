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

    maven("https://s01.oss.sonatype.org/content/repositories/snapshots") //KOTEST snapshot
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
