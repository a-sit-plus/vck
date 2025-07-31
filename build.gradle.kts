import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family
import java.io.ByteArrayOutputStream

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val kotestVer = System.getenv("KOTEST_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotest.get()
    val kspVer = System.getenv("KSP_VERSION_ENV")?.ifBlank { null } ?: "$kotlinVer-${libs.versions.ksp.get()}"

    id("at.asitplus.gradle.conventions") version "20250728"
    id("io.kotest") version kotestVer
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.library") version libs.versions.agp.get() apply (false)
    id("com.google.devtools.ksp") version kspVer
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

subprojects {
    this.afterEvaluate {
        //doesn't build with latest signum, but doesn't matter either
        tasks.findByName("iosX64Test")?.let { it.enabled = false }
        tasks.findByName("linkDebugTestIosX64")?.let { it.enabled = false }

        /*help the linker (yes, this is absolutely bonkers!)*/
        if (org.gradle.internal.os.OperatingSystem.current() == org.gradle.internal.os.OperatingSystem.MAC_OS) {
            val devDir = System.getenv("DEVELOPER_DIR")?.ifEmpty { null }.let {
                if (it == null) {
                    val output = ByteArrayOutputStream()
                    project.exec {
                        commandLine("xcode-select", "-p")
                        standardOutput = output
                    }
                    output.toString().trim()
                } else it
            }

            logger.lifecycle("  DEV DIR points to $devDir")

            val swiftLib = "$devDir/Toolchains/XcodeDefault.xctoolchain/usr/lib/swift/"

            extensions.getByType<KotlinMultiplatformExtension>().targets.withType<KotlinNativeTarget>()
                .configureEach {
                    val sub = when (konanTarget.family) {
                        Family.IOS ->
                            if (konanTarget.name.contains("SIMULATOR", true)) "iphonesimulator" else "iphoneos"

                        Family.OSX -> "macosx"
                        Family.TVOS ->
                            if (konanTarget.name.contains("SIMULATOR", true)) "appletvsimulator" else "appletvos"

                        Family.WATCHOS ->
                            if (konanTarget.name.contains("SIMULATOR", true)) "watchsimulator" else "watchos"

                        else -> throw StopExecutionException("Konan target ${konanTarget.name} is not recognized")
                    }

                    logger.lifecycle("  KONAN target is ${konanTarget.name} which resolves to $sub")
                    binaries.all {
                        linkerOpts(
                            "-L${swiftLib}$sub",
                            "-L/usr/lib/swift"
                        )
                    }
                }
        }
    }
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

afterEvaluate {
    nexusPublishing {
        repositories {
            named("sonatype") {
                nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
                snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
            }
        }
    }
}
