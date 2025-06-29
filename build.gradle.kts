import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    kotlin("multiplatform") version  libs.versions.kotlin apply false
    kotlin("plugin.serialization") version libs.versions.kotlin apply false
    id("io.kotest.multiplatform") version libs.versions.kotest
    id("at.asitplus.gradle.vclib-conventions")
}

//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(layout.buildDirectory.dir("dokka").get().asFile)
    includes.from("README.md")
    doLast {
        files(
            "vck-dark.png",
            "vck-light.png",
            "eu.svg",
        ).files.forEach { it.copyTo(File("build/dokka/${it.name}"), overwrite = true) }
    }
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion
