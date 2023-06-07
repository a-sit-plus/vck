@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")
package at.asitplus.gradle

import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension

internal inline fun KotlinMultiplatformExtension.experimentalOptIns() {
    targets.all {
        compilations.all {
            kotlinOptions {
                freeCompilerArgs = listOf(
                    "-opt-in=kotlinx.serialization.ExperimentalSerializationApi",
                    "-opt-in=kotlinx.coroutines.ExperimentalCoroutinesApi",
                    "-opt-in=kotlin.time.ExperimentalTime",
                    "-opt-in=kotlin.RequiresOptIn",
                )
            }
        }
    }
}