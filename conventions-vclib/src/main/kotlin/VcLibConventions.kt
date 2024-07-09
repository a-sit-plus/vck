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
    project.AspVersions.versions["encoding"] = kmpCryptoVersionCatalog.findVersion("encoding").get().toString()


    return listOf(
        coroutines(),
        serialization("json"),
        serialization("cbor"),
        addDependency("at.asitplus.crypto:datatypes", "kmpcrypto"), //for iOS Export
        addDependency("at.asitplus.crypto:datatypes-cose", "kmpcrypto"),
        addDependency("at.asitplus.crypto:datatypes-jws", "kmpcrypto"),
        addDependency("at.asitplus:jsonpath", "jsonpath"),
        datetime(),
        addDependency("com.squareup.okio:okio", "okio"),
        addDependency("io.matthewnelson.kotlin-components:encoding-base16", "encoding"),
        addDependency("io.matthewnelson.kotlin-components:encoding-base64", "encoding"),
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
    "at.asitplus.crypto:datatypes:${VcLibVersions.kmpcrypto}",
    "at.asitplus.crypto:datatypes-cose:${VcLibVersions.kmpcrypto}",
    "at.asitplus.crypto:datatypes-jws:${VcLibVersions.kmpcrypto}",
    "at.asitplus:jsonpath:${VcLibVersions.jsonpath}",
    "io.matthewnelson.kotlin-components:encoding-base16:${kmpCryptoVersionCatalog.findVersion("encoding").get()}",
    "io.matthewnelson.kotlin-components:encoding-base64:${kmpCryptoVersionCatalog.findVersion("encoding").get()}",
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

