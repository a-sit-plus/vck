@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


inline fun commonApiDependencies() = listOf(
    coroutines(),
    serialization("json"),
    serialization("cbor"),
    "at.asitplus.crypto:datatypes-cose:${VcLibVersions.kmpcrypto}",
    "at.asitplus.crypto:datatypes-jws:${VcLibVersions.kmpcrypto}",
    datetime(),
    "com.benasher44:uuid:${VcLibVersions.uuid}",
    "com.squareup.okio:okio:${VcLibVersions.okio}",
    "io.matthewnelson.kotlin-components:encoding-base16:${VcLibVersions.encoding}",
    "io.matthewnelson.kotlin-components:encoding-base64:${VcLibVersions.encoding}"
)

inline fun KotlinDependencyHandler.commonImplementationAndApiDependencies() {
    commonApiDependencies().forEach { dep -> api(dep) }
    commonImplementationDependencies()
}
inline fun KotlinDependencyHandler.commonImplementationDependencies() {
    implementation(ktor("http"))
    implementation(napier())
    implementation(ktor("utils"))
}

fun commonIosExports() = arrayOf(
    datetime(),
    kmmresult(),
    "at.asitplus.crypto:datatypes:${VcLibVersions.kmpcrypto}",
    "at.asitplus.crypto:datatypes-cose:${VcLibVersions.kmpcrypto}",
    "at.asitplus.crypto:datatypes-jws:${VcLibVersions.kmpcrypto}",
    "io.matthewnelson.kotlin-components:encoding-base16:${VcLibVersions.encoding}",
    "io.matthewnelson.kotlin-components:encoding-base64:${VcLibVersions.encoding}",
)


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.plugins.apply("at.asitplus.gradle.conventions")
    }
}

