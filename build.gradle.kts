import org.gradle.kotlin.dsl.support.listFilesOrdered
import org.jetbrains.dokka.DokkaDefaults.moduleName
import at.asitplus.gradle.dokka
import at.asitplus.gradle.html
import org.jetbrains.dokka.gradle.tasks.DokkaBaseTask
import java.time.Duration

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer = System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()
    id("de.infix.testBalloon") version testballoonVer apply false
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("at.asitplus.gradle.conventions")
}

val dokkaDir = rootProject.layout.buildDirectory.dir("docs")
dokka {
    dokkaPublications.html{
        outputDirectory.set(dokkaDir)
        includes.from("README.md")
    }
}


tasks.getByName("dokkaGenerate") {
    this as DokkaBaseTask
    doLast {
        files(
            "vck-dark.png",
            "vck-light.png",
            "eu.svg",
        ).files.forEach { it.copyTo(File("${dokkaDir.get()}/${it.name}"), overwrite = true) }
    }
}


subprojects {
    rootProject.dependencies.add("dokka", this)
    }
    afterEvaluate {
        //doesn't build with latest signum, but doesn't matter either
        tasks.findByName("iosX64Test")?.let { it.enabled = false }
        tasks.findByName("linkDebugTestIosX64")?.let { it.enabled = false }
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

//massive timeouts for nexus publishing to cope with the sheer number and size of artefacts
nexusPublishing {
    transitionCheckOptions {
        maxRetries.set(200)
        delayBetween.set(Duration.ofSeconds(20))
    }
    connectTimeout.set(Duration.ofMinutes(15))
    clientTimeout.set(Duration.ofMinutes(15))
}