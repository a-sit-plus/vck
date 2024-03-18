import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
plugins {
    id("at.asitplus.gradle.vclib-conventions")
}

//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(layout.buildDirectory.dir("dokka").get().asFile)
    includes.from("README.md")
}

task<Exec>("purge") {
    dependsOn("clean")
    workingDir = layout.projectDirectory.dir("vclib").asFile
    commandLine("./gradlew", "clean")
    doFirst {
        println("descending into ${workingDir.absolutePath}")
        logger.lifecycle("Purging VcLib maven build")
    }
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion
