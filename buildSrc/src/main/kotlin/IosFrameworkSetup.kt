@file:Suppress("NOTHING_TO_INLINE")

import org.gradle.api.Project
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.Framework
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFrameworkConfig


inline fun Framework.addCommonExports() {
    export("org.jetbrains.kotlinx:kotlinx-datetime:${Versions.datetime}")
    export("at.asitplus:kmmresult:${Versions.resultlib}")
    export("io.matthewnelson.kotlin-components:encoding-base16:${Versions.encoding}")
    export("io.matthewnelson.kotlin-components:encoding-base64:${Versions.encoding}")
}
