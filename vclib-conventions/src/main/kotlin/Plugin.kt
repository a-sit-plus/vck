package at.asitplus.gradle

import VcLibVersions
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler

inline fun KotlinDependencyHandler.commonImplementationDependencies() {
    implementation(serialization("json"))
    implementation(coroutines())
    implementation("com.benasher44:uuid:${VcLibVersions.uuid}")
    implementation("io.ktor:ktor-http:${VcLibVersions.ktor}")
    implementation("io.ktor:ktor-utils:${VcLibVersions.ktor}")
    implementation("com.squareup.okio:okio:${VcLibVersions.okio}")
    implementation(napier())
}

fun commonIosExports() = arrayOf(
    datetime(),
    "at.asitplus:kmmresult:${VcLibVersions.resultlib}",
    "io.matthewnelson.kotlin-components:encoding-base16:${VcLibVersions.encoding}",
    "io.matthewnelson.kotlin-components:encoding-base64:${VcLibVersions.encoding}",
)


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
       target.plugins.apply("at.asitplus.gradle.conventions")
    }
}

