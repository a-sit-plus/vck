@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")
package at.asitplus.gradle

import org.gradle.api.Project
import org.gradle.kotlin.dsl.getByType
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.plugin.mpp.Framework
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFrameworkConfig


fun Project.exportIosFramework(name: String, vararg additionalExport: Any){
    extensions.getByType<KotlinMultiplatformExtension>().apply{
        XCFrameworkConfig(project, name).also { xcf ->
            ios {
                binaries.framework {
                    baseName = name
                    embedBitcode("bitcode")
                    additionalExport.forEach {
                        export(it)
                    }
                    xcf.add(this)
                }
            }
            iosSimulatorArm64 {
                binaries.framework {
                    baseName = name
                    embedBitcode("bitcode")
                    additionalExport.forEach {
                        export(it)
                    }
                    xcf.add(this)
                }
            }
        }
    }
}