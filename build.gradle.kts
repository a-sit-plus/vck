import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.vclib-conventions")
    id("com.android.library") version "8.2.0" apply (false)
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
        ).files.forEach { it.copyTo(File("build/dokka/${it.name}"), overwrite = true) }
    }
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion