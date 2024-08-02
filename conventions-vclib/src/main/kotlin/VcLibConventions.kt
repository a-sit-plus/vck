@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler
import org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask
import org.jetbrains.kotlin.gradle.utils.named


val Project.kmpCryptoVersionCatalog: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("kmpCrypto")

inline fun Project.commonApiDependencies(): List<String> {
    project.AspVersions.versions["kmpcrypto"] = VcLibVersions.kmpcrypto
    project.AspVersions.versions["jsonpath"] = VcLibVersions.jsonpath
    project.AspVersions.versions["okio"] = kmpCryptoVersionCatalog.findVersion("okio").get().toString()
    project.AspVersions.versions["encoding"] = "2.2.1"


    return listOf(
        coroutines(),
        serialization("json"),
        serialization("cbor"),
        addDependency("at.asitplus.signum:indispensable", "kmpcrypto"), //for iOS Export
        addDependency("at.asitplus.signum:indispensable-cosef", "kmpcrypto"),
        addDependency("at.asitplus.signum:indispensable-josef", "kmpcrypto"),
        addDependency("at.asitplus:jsonpath4k", "jsonpath"),
        datetime(),
        addDependency("com.squareup.okio:okio", "okio"),
        addDependency("io.matthewnelson.encoding:base16", "encoding"),
        addDependency("io.matthewnelson.encoding:base64", "encoding"),
        addDependency("io.matthewnelson.encoding:core", "encoding"),
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
    project.AspVersions.versions["uuid"] = VcLibVersions.uuid
    implementation(project.addDependency("com.benasher44:uuid", "uuid"))
}


fun Project.commonIosExports() = arrayOf(
    datetime(),
    "com.ionspin.kotlin:bignum:${kmpCryptoVersionCatalog.findVersion("bignum").get()}",
    kmmresult(),
    "at.asitplus.signum:indispensable:${VcLibVersions.kmpcrypto}",
    "at.asitplus.signum:indispensable-cosef:${VcLibVersions.kmpcrypto}",
    "at.asitplus.signum:indispensable-josef:${VcLibVersions.kmpcrypto}",
    "at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}",
    "io.matthewnelson.encoding:core:${AspVersions.versions["encoding"]}",
    "io.matthewnelson.encoding:base16:${AspVersions.versions["encoding"]}",
    "io.matthewnelson.encoding:base64:${AspVersions.versions["encoding"]}",
)


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.plugins.apply("at.asitplus.gradle.conventions")
        target.gradle.taskGraph.whenReady {
            target.tasks.withType<KotlinCompilationTask<*>>().configureEach {
                compilerOptions {
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                    optIn.add("kotlinx.cinterop.BetaInteropApi")
                }
            }
        }

    }
}

