@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import java.io.File
import java.util.Properties
import com.android.build.api.dsl.androidLibrary
import com.android.build.api.variant.KotlinMultiplatformAndroidComponentsExtension
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.invoke
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler

val Project.signumVersionCatalog: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("signum")

val Project.VcLibVersions get() = VcLibVersions(this)

inline fun Project.commonApiDependencies(): List<String> {
    project.AspVersions.versions["signum"] = VcLibVersions.signum
    project.AspVersions.versions["supreme"] = VcLibVersions.supreme
    project.AspVersions.versions["jsonpath"] = VcLibVersions.jsonpath


    return listOf(
        coroutines(),
        addDependency("at.asitplus.signum:supreme", "supreme"),
        addDependency("at.asitplus.signum:indispensable-cosef", "signum"),
        addDependency("at.asitplus.signum:indispensable-josef", "signum"),
        addDependency("at.asitplus:jsonpath4k", "jsonpath"),
    )
}

inline fun KotlinDependencyHandler.commonImplementationAndApiDependencies() {
    project.commonApiDependencies().forEach { dep -> api(dep) }
    commonImplementationDependencies()
}


inline fun KotlinDependencyHandler.commonImplementationDependencies() {
    implementation(project.ktor("http"))
    implementation(project.napier())
    implementation(project.ktor("utils"))
    implementation("net.orandja.obor:obor:${project.VcLibVersions.obor}")
}

class VcLibConventions : K2Conventions() {
    override fun apply(target: Project) {
        target.keepAndroidJvmTarget = true // keep androidJvmMain wiring even if no AGP is applied
        super.apply(target)
        if (target.rootProject != target) {
            target.pluginManager.apply("org.jetbrains.kotlin.multiplatform")
            target.pluginManager.apply("org.jetbrains.kotlin.plugin.serialization")
            if (target.hasAndroidSdk()) {
                target.pluginManager.apply("com.android.kotlin.multiplatform.library")
            }
            target.pluginManager.apply("signing")
            target.pluginManager.apply("org.jetbrains.dokka")
            target.pluginManager.apply("de.infix.testBalloon")
            target.pluginManager.apply("maven-publish")
            //if we do this properly, cinterop (swift-klib) blows up, so we hack!
            target.afterEvaluate {

                extensions.getByType<KotlinMultiplatformExtension>().apply {
                    sourceSets.forEach {
                        it.languageSettings.enableLanguageFeature("ContextParameters")
                    }
                    sourceSets.commonTest.get()
                        .dependencies { implementation("at.asitplus.gradle:testballoon-shim:$buildDate") }
                }
                tasks.withType<Test>().configureEach {
                    maxHeapSize = "4G"
                }

                target.compileVersionCatalog()
                target.setupSignDependency()
            }
        }
    }
}

fun KotlinMultiplatformExtension.vckAndroid(minSdkOverride: Int? = null)  {
    if (!project.hasAndroidSdk()) {
        project.logger.lifecycle("  \u001b[7m\u001b[1mAndroid SDK not found; skipping Android artifact.\u001b[0m")
        return
    }
    val compat = project.androidJvmTarget
    androidLibrary {
        compilations.configureEach {
            if (name.contains("test", ignoreCase = true)) {
                if (project.raiseAndroidTestToJdkTarget) compilerOptions.configure {
                    jvmTarget.set(JvmTarget.fromTarget(project.jvmTarget))
                }
            } else compilerOptions.configure {
                jvmTarget.set(JvmTarget.fromTarget(compat!!))
            }
        }

        namespace = "${project.group}.${project.name.replace('-', '.')}"
        minSdk = project.androidMinSdk
        minSdkOverride?.let {
            project.logger.lifecycle("  \u001b[7m\u001b[1m" + "Overriding Android defaultConfig minSDK to $minSdkOverride for project ${project.name}" + "\u001b[0m")
            minSdk = it
        }
        compileSdk = project.androidCompileSdk

        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunnerArguments["timeout_msec"] = "2400000"
            managedDevices {
                localDevices {
                    create("pixelAVD").apply {
                        device = "Pixel 4"
                        apiLevel = 35
                        systemImageSource = "aosp-atd"
                    }
                }
            }
        }
        packaging {
            listOf(
                "org/bouncycastle/pqc/crypto/picnic/lowmcL5.bin.properties",
                "org/bouncycastle/pqc/crypto/picnic/lowmcL3.bin.properties",
                "org/bouncycastle/pqc/crypto/picnic/lowmcL1.bin.properties",
                "org/bouncycastle/x509/CertPathReviewerMessages_de.properties",
                "org/bouncycastle/x509/CertPathReviewerMessages.properties",
                "org/bouncycastle/pkix/CertPathReviewerMessages_de.properties",
                "org/bouncycastle/pkix/CertPathReviewerMessages.properties",
                "/META-INF/{AL2.0,LGPL2.1}",
                "win32-x86-64/attach_hotspot_windows.dll",
                "win32-x86/attach_hotspot_windows.dll",
                "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
                "META-INF/licenses/*",
                //noinspection WrongGradleMethod
            ).forEach { resources.excludes.add(it) }
        }
    }
    sourceSets.whenObjectAdded {
        if (this.name == "androidDeviceTest") {
            dependencies {
                implementation("de.infix.testBalloon:testBalloon-framework-core:${project.AspVersions.testballoon}")
                implementation("androidx.test:runner:${project.AspVersions.androidTestRunner}")
            }
        }
    }
    sourceSets.findByName("androidDeviceTest")?.dependencies {
        implementation("de.infix.testBalloon:testBalloon-framework-core:${project.AspVersions.testballoon}")
        implementation("androidx.test:runner:${project.AspVersions.androidTestRunner}")
    }
    project.extensions.getByType<KotlinMultiplatformAndroidComponentsExtension>().apply {
        onVariants { v ->
            // Configure the instrumented-test APK only
            v.androidTest?.manifestPlaceholders?.put("testLargeHeap", "true")
        }
    }
}

fun Project.hasAndroidSdk() = resolveAndroidSdk(this)?.let { it -> isValidAndroidSdk(it) } == true

private fun resolveAndroidSdk(project: Project): File? {
    // Highest precedence: ANDROID_SDK_ROOT (preferred), then ANDROID_HOME (legacy)
    val env = System.getenv()
    val fromEnv = listOf("ANDROID_SDK_ROOT", "ANDROID_HOME")
        .asSequence()
        .mapNotNull { env[it]?.takeIf { it.isNotBlank() } }
        .map(::File)
        .firstOrNull { it.exists() }

    if (fromEnv != null) return fromEnv

    // Fallback: local.properties (common on dev machines)
    val localProps = File(project.rootDir, "local.properties")
    if (localProps.exists()) {
        Properties().apply {
            localProps.inputStream().use(::load)
            (getProperty("sdk.dir") ?: getProperty("android.sdk.path"))?.let {
                val f = File(it)
                if (f.exists()) return f
            }
        }
    }
    return null
}

private fun isValidAndroidSdk(sdk: File): Boolean {
    val platformsOk = File(sdk, "platforms").listFiles()?.any { it.isDirectory } == true
    val buildToolsOk = File(sdk, "build-tools").listFiles()?.any { it.isDirectory } == true
    return platformsOk && buildToolsOk
}
