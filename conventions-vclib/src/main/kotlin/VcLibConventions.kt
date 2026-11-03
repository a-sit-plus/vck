@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import org.gradle.api.Plugin
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


inline fun Project.commonApiDependencies(): List<String> {
    return listOf(
        coroutines(),
        serialization("json"),
        serialization("cbor"),
        kmmresult(),
        datetime(),
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

class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.plugins.apply("at.asitplus.gradle.conventions")
    }
}

