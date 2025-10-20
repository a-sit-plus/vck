@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import com.android.build.api.dsl.androidLibrary
import com.android.build.api.variant.KotlinMultiplatformAndroidComponentsExtension
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.api.tasks.testing.Test
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.invoke
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

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
        super.apply(target)
        if (target.rootProject != target) {
            target.pluginManager.apply("org.jetbrains.kotlin.multiplatform")
            target.pluginManager.apply("org.jetbrains.kotlin.plugin.serialization")
            target.pluginManager.apply("com.android.kotlin.multiplatform.library")
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
                    sourceSets.commonMain.get()
                        .dependencies { implementation("at.asitplus.gradle:testballoon-shim:$buildDate") }
                }
                tasks.withType<Test>().configureEach {
                    maxHeapSize = "4G"
                }

            }
        }
    }
}

fun Project.vckAndroid(minSdkOverride: Int? = null) = extensions.getByType<KotlinMultiplatformExtension>().apply {
    val namespace = "${project.group}.${project.name.replace('-', '.')}"
    androidLibrary {
        this.namespace = namespace
        minSdkOverride?.let {
            project.logger.lifecycle("  \u001b[7m\u001b[1m" + "Overriding Android defaultConfig minSDK to $minSdkOverride for project ${project.name}" + "\u001b[0m")
            minSdk = it
        }
        compileSdk = androidCompileSdk

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
    project.extensions.getByType<KotlinMultiplatformAndroidComponentsExtension>().apply {
        onVariants { v ->
            // Configure the instrumented-test APK only
            v.androidTest?.manifestPlaceholders?.put("testLargeHeap", "true")
        }
    }
}