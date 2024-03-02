@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


inline fun commonDependencies() = listOf(
    coroutines(),
    serialization("json"),
    napier(),
    "com.benasher44:uuid:${VcLibVersions.uuid}",
    "com.squareup.okio:okio:${VcLibVersions.okio}"


)

inline fun KotlinDependencyHandler.commonImplementationDependencies() {
    commonDependencies().forEach { dep -> implementation(dep) }
    implementation(ktor("http"))
    implementation(ktor("utils"))
}

fun commonIosExports() = arrayOf(
    datetime(),
    kmmresult(),
    "io.matthewnelson.kotlin-components:encoding-base16:${VcLibVersions.encoding}",
    "io.matthewnelson.kotlin-components:encoding-base64:${VcLibVersions.encoding}",
)


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.plugins.apply("at.asitplus.gradle.conventions")
    }
}

