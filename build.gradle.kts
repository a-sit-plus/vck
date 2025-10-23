import org.jetbrains.dokka.gradle.DokkaMultiModuleTask
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget
import org.jetbrains.kotlin.konan.target.Family
import java.io.ByteArrayOutputStream

plugins {
    val kotlinVer = System.getenv("KOTLIN_VERSION_ENV")?.ifBlank { null } ?: libs.versions.kotlin.get()
    val testballoonVer = System.getenv("TESTBALLOON_VERSION_OVERRIDE")?.ifBlank { null } ?: libs.versions.testballoon.get()

    id("at.asitplus.gradle.conventions")
    kotlin("multiplatform") version kotlinVer apply false
    kotlin("plugin.serialization") version kotlinVer apply false
    id("com.android.kotlin.multiplatform.library") version libs.versions.agp.get() apply (false)
    id("de.infix.testBalloon") version testballoonVer apply false
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
    afterEvaluate {
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
