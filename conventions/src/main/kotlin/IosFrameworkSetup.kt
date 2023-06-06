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

class StrHolder(val ext: KotlinMultiplatformExtension, val name: String, val additionalExport: Array<out Any>) {
    inline infix fun from(project: Project) {
        XCFrameworkConfig(project, name).also { xcf ->
            ext.ios {
                binaries.framework {
                    baseName = name
                    embedBitcode("bitcode")
                    addCommonExports()
                    additionalExport.forEach {
                        export(it)
                    }
                    xcf.add(this)
                }
            }
            ext.iosSimulatorArm64 {
                binaries.framework {
                    baseName = name
                    embedBitcode("bitcode")
                    addCommonExports()
                    additionalExport.forEach {
                        export(it)
                    }
                    xcf.add(this)
                }
            }
        }

    }
}


inline fun KotlinMultiplatformExtension.iosFramework(name: String, vararg additionalExport: Any) =
    StrHolder(this, name, additionalExport)
