@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import AspVersions
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


fun String?.toSuffix() = this?.let { "-$it" } ?: ""

internal inline fun KotlinDependencyHandler.addKotest(target: String? = null) {
    val targetInfo = target?.let { " ($it)" } ?: ""
    println("  Adding Kotest libraries:")
    println("   * Assertions$targetInfo")
    println("   * Property-based testing$targetInfo")
    println("   * Datatest$targetInfo")
    implementation(kotest("assertions-core", target))
    implementation(kotest("common", target))
    implementation(kotest("property", target))
    implementation(kotest("framework-engine", target))
    implementation(kotest("framework-datatest", target))
}

@JvmOverloads
inline fun kotest(module: String, target: String? = null) =
    "io.kotest:kotest-$module${target.toSuffix()}:${AspVersions.kotest}"

internal inline fun KotlinDependencyHandler.addKotestJvmRunner() {
    println("  Adding Kotest JUnit runner")
    implementation(kotest("runner-junit5", "jvm"))
}

@JvmOverloads
inline fun serialization(format: String, target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-serialization-$format${target.toSuffix()}:${AspVersions.serialization}"

@JvmOverloads
inline fun ktor(module: String, target: String? = null) =
    "io.ktor:ktor-$module${target.toSuffix()}:${AspVersions.ktor}"

@JvmOverloads
inline fun coroutines(target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-coroutines-core${target.toSuffix()}:${AspVersions.coroutines}"

@JvmOverloads
inline fun napier(target: String? = null) =
    "io.github.aakira:napier${target.toSuffix()}:${AspVersions.napier}"

@JvmOverloads
inline fun datetime(target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-datetime${target.toSuffix()}:${AspVersions.datetime}"

@JvmOverloads
inline fun bouncycastle(module: String, classifier: String = "jdk18on") =
    "org.bouncycastle:$module-$classifier:${AspVersions.Jvm.bouncycastle}"
