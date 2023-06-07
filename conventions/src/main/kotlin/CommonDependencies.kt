@file:Suppress("NOTHING_TO_INLINE")

package at.asitplus.gradle

import AspVersions
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


internal inline fun KotlinDependencyHandler.addKotest(target: String? = null) {
    val suffix = target.toSuffix()
    val targetInfo = target?.let { " ($it)" } ?: ""
    println("Adding Kotest libraries:")
    println("   * Assertions$targetInfo")
    println("   * Property-based testing$targetInfo")
    println("   * Datatest$targetInfo")
    implementation("io.kotest:kotest-assertions-core$suffix:${AspVersions.kotest}")
    implementation("io.kotest:kotest-common$suffix:${AspVersions.kotest}")
    implementation("io.kotest:kotest-property$suffix:${AspVersions.kotest}")
    implementation("io.kotest:kotest-framework-engine$suffix:${AspVersions.kotest}")
    implementation("io.kotest:kotest-framework-datatest$suffix:${AspVersions.kotest}")
}

fun String?.toSuffix() = this?.let { "-$it" } ?: ""

internal inline fun KotlinDependencyHandler.addKotestJvmRunner() {
    println("Adding Kotest JUnit Runner")
    implementation("io.kotest:kotest-runner-junit5-jvm:${AspVersions.kotest}")
}

inline fun serialization(format: String, target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-serialization-$format${target.toSuffix()}:${AspVersions.serialization}"

inline fun coroutines(target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-coroutines-core${target.toSuffix()}:${AspVersions.coroutines}"
inline fun napier(target: String? = null) =
    "io.github.aakira:napier${target.toSuffix()}:${AspVersions.napier}"

inline fun datetime(target: String? = null) =
    "org.jetbrains.kotlinx:kotlinx-datetime${target.toSuffix()}:${AspVersions.datetime}"
inline fun bouncycastle(module:String, classifier:String="jdk18on") =
    "org.bouncycastle:$module-$classifier:${AspVersions.Jvm.bouncycastle}"
