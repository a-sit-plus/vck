import at.asitplus.gradle.AspVersions
import at.asitplus.gradle.VcLibVersions
import at.asitplus.gradle.envExtra
import at.asitplus.gradle.kotest
import at.asitplus.gradle.napier
import co.touchlab.skie.configuration.EnumInterop
import co.touchlab.skie.configuration.SealedInterop
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFramework

/*
 * Swift-facing bridge for iOS apps: Apple-specific adapters (SecKey, SecCertificate), Swift-friendly builders, defaults,
 * serializers, and bridges for HTTP exchanges and suspend functions, bundled together with all VC-K modules into one XCFramework, which `Package.swift` in the repository root
 * ships as a Swift package. Not published to Maven.
 */
plugins {
    id("at.asitplus.gradle.vclib-conventions")
    alias(libs.plugins.skie)
}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

/** Name of the XCFramework and Swift module, i.e. `import VckIos`, must match `Package.swift`. */
val xcframeworkName = "VckIos"

val disableAppleTargets by envExtra
if ("true" != disableAppleTargets) {
    val exportedDependencies = listOf(
        project(":vck"),
        project(":vck-openid"),
        project(":vck-openid-ktor"),
        project(":openid-data-classes"),
        project(":csc-data-classes"),
        "at.asitplus.signum:indispensable:${VcLibVersions.signum}",
        "at.asitplus.signum:indispensable-josef:${VcLibVersions.signum}",
        "at.asitplus.signum:indispensable-cosef:${VcLibVersions.signum}",
        "at.asitplus.signum:supreme:${VcLibVersions.supreme}",
        "at.asitplus:kmmresult:${AspVersions.versions["kmmresult"]}",
        napier(),
    )
    val xcf = XCFramework(xcframeworkName)

    kotlin {
        listOf(
            iosArm64(),
            iosSimulatorArm64(),
        ).forEach { iosTarget ->
            iosTarget.binaries.framework {
                baseName = xcframeworkName
                binaryOption("bundleId", "at.asitplus.wallet.$xcframeworkName")
                isStatic = true
                xcf.add(this)
                exportedDependencies.forEach { export(it) }
            }
        }

        sourceSets {
            iosMain {
                dependencies {
                    exportedDependencies.forEach { api(it) }
                }
            }
            iosTest {
                dependencies {
                    implementation(kotest("assertions-core"))
                }
            }
        }
    }

    skie {
        features {
            defaultArgumentsInExternalLibraries.set(false)
            group {
                SealedInterop.ExportEntireHierarchy(true)
            }
            group("at.asitplus.signum.indispensable.HMAC") {
                EnumInterop.Enabled(false)
            }
        }
    }
}

// Ships through Swift Package Manager only, see Package.swift
tasks.withType<AbstractPublishToMaven>().configureEach { enabled = false }
