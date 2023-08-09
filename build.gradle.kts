plugins {
    id("at.asitplus.gradle.vclib-conventions")
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