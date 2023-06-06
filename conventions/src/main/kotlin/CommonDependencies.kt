@file:Suppress("NOTHING_TO_INLINE")

import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler


inline fun KotlinDependencyHandler.commonImplementationDependencies() {
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.coroutines}")
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.`serialization-json`}")
    implementation("com.benasher44:uuid:${Versions.uuid}")
    implementation("io.ktor:ktor-http:${Versions.ktor}")
    implementation("io.ktor:ktor-utils:${Versions.ktor}")
    implementation("com.squareup.okio:okio:${Versions.okio}")
    implementation("io.github.aakira:napier:${Versions.napier}")
}

internal inline fun KotlinDependencyHandler.commonTestDependencies() {
    implementation("io.kotest:kotest-assertions-core:${Versions.kotest}")
    implementation("io.kotest:kotest-common:${Versions.kotest}")
    implementation("io.kotest:kotest-property:${Versions.kotest}")
    implementation("io.kotest:kotest-framework-engine:${Versions.kotest}")
    implementation("io.kotest:kotest-framework-datatest:${Versions.kotest}")
}