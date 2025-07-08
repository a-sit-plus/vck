@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


inline fun Project.commonApiDependencies(): List<String> {
    project.AspVersions.versions["okio"] = VcLibVersions.okio
    project.AspVersions.versions["encoding"] = VcLibVersions.encoding
    return listOf(
        coroutines(),
        serialization("json"),
        serialization("cbor"),
        kmmresult(),
        datetime(),
        addDependency("com.squareup.okio:okio", "okio"),
        addDependency("io.matthewnelson.encoding:base16", "encoding"),
        addDependency("io.matthewnelson.encoding:base64", "encoding"),
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
}

fun Project.commonIosExports() = arrayOf(
    datetime(),
    kmmresult(),
    "io.matthewnelson.encoding:base16:${VcLibVersions.encoding}",
    "io.matthewnelson.encoding:base16:${VcLibVersions.encoding}",
)


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.plugins.apply("at.asitplus.gradle.conventions")
    }
}

