plugins {
    id("at.asitplus.gradle.conventions")
    //id("io.github.gradle-nexus.publish-plugin") version "1.1.0"
}
/*
buildscript {
    repositories {
        gradlePluginPortal()
        mavenCentral()
    }
}*/
/*
allprojects {
    repositories {
        google()
        mavenCentral()
    }
}*/

tasks.register<Delete>("clean") {
    doFirst { println("Cleaning all build files") }

    delete(rootProject.buildDir)
    delete(layout.projectDirectory.dir("repo"))
    doLast { println("Clean done") }
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

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
        }
    }
}

