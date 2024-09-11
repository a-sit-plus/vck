@file:Suppress("NOTHING_TO_INLINE", "PackageDirectoryMismatch")

package at.asitplus.gradle

import VcLibVersions
import com.android.build.gradle.LibraryExtension
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.FunSpec
import com.squareup.kotlinpoet.TypeSpec
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.artifacts.VersionCatalog
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.dependencies
import org.gradle.kotlin.dsl.getByName
import org.gradle.kotlin.dsl.getByType
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.plugin.KotlinDependencyHandler
import org.jetbrains.kotlin.gradle.tasks.KotlinCompilationTask
import java.io.FileInputStream
import java.util.regex.Pattern

val Project.signumVersionCatalog: VersionCatalog
    get() = extensions.getByType<VersionCatalogsExtension>().named("signum")

inline fun Project.commonApiDependencies(): List<String> {
    project.AspVersions.versions["signum"] = VcLibVersions.signum
    project.AspVersions.versions["supreme"] = VcLibVersions.supreme
    project.AspVersions.versions["jsonpath"] = VcLibVersions.jsonpath
    project.AspVersions.versions["okio"] = signumVersionCatalog.findVersion("okio").get().toString()
    project.AspVersions.versions["encoding"] = "2.2.1"


    return listOf(
        coroutines(),
        serialization("json"),
        serialization("cbor"),
        addDependency("at.asitplus.signum:supreme", "supreme"), //for iOS Export
        addDependency("at.asitplus.signum:indispensable-cosef", "signum"),
        addDependency("at.asitplus.signum:indispensable-josef", "signum"),
        datetime(),
        addDependency("com.squareup.okio:okio", "okio"),
        addDependency("io.matthewnelson.encoding:base16", "encoding"),
        addDependency("io.matthewnelson.encoding:base64", "encoding"),
        addDependency("io.matthewnelson.encoding:core", "encoding"),
        addDependency("at.asitplus:jsonpath4k", "jsonpath"),
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
    project.AspVersions.versions["uuid"] = VcLibVersions.uuid
    implementation(project.addDependency("com.benasher44:uuid", "uuid"))
}


fun Project.commonIosExports() = arrayOf(
    datetime(),
    "com.ionspin.kotlin:bignum:${signumVersionCatalog.findVersion("bignum").get()}",
    kmmresult(),
    "at.asitplus.signum:supreme:${VcLibVersions.supreme}",
    "at.asitplus.signum:indispensable:${VcLibVersions.signum}",
    "at.asitplus.signum:indispensable-cosef:${VcLibVersions.signum}",
    "at.asitplus.signum:indispensable-josef:${VcLibVersions.signum}",
    "at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}",
    "io.matthewnelson.encoding:core:${AspVersions.versions["encoding"]}",
    "io.matthewnelson.encoding:base16:${AspVersions.versions["encoding"]}",
    "io.matthewnelson.encoding:base64:${AspVersions.versions["encoding"]}",
)


/**
 * Hooks up Kotest tests from common using a frankensteined JUnit runner.
 * It generates code using KotlinPoet to hook it up as per https://github.com/kotest/kotest/issues/189
 */
inline fun Project.wireAndroidInstrumentedTests() {
    logger.lifecycle("  Wiring up Android Instrumented Tests")
    val targetDir = project.layout.projectDirectory.dir("src")
        .dir("androidInstrumentedTest").dir("kotlin")
        .dir("generated").asFile.apply { deleteRecursively() }

    val packagePattern = Pattern.compile("package\\s+(\\S+)", Pattern.UNICODE_CHARACTER_CLASS)
    val searchPattern =
        Pattern.compile("\\s+class\\s+(\\S+)\\s*:\\s*FreeSpec", Pattern.UNICODE_CHARACTER_CLASS)
    project.layout.projectDirectory.dir("src").dir("commonTest")
        .dir("kotlin").asFileTree.filter { it.extension == "kt" }.forEach { file ->
            FileInputStream(file).bufferedReader().use { reader ->
                val source = reader.readText()

                val packageName = packagePattern.matcher(source).run {
                    if (find()) group(1) else null
                }

                val matcher = searchPattern.matcher(source)

                while (matcher.find()) {
                    val className = matcher.group(1)
                    logger.lifecycle("Found Test class $className in file ${file.name}")

                    FileSpec.builder("at.asitplus.wallet.instrumented", "Android$className")
                        .addType(
                            TypeSpec.classBuilder("Android$className")
                                .apply {
                                    // this.superclass(ClassName(packageName ?: "", className))
                                    addFunction(
                                        FunSpec.Companion.builder("test").addCode(
                                            "%L",
                                            """
                                            val listener = io.kotest.engine.listener.CollectingTestEngineListener()
                                            io.kotest.engine.TestEngineLauncher(listener)
                                                .withClasses(
                                                """.trimIndent()
                                                    + ClassName(
                                                packageName ?: "",
                                                className
                                            ).canonicalName + "::class)" +
                                                    """
                                            .launch()
                                            listener.tests.map { entry ->
                                                {
                                                    val testCase = entry.key
                                                    val descriptor = testCase.descriptor.chain().joinToString(" > ") {
                                                        it.id.value
                                                    }
                                                    val cause = when (val value = entry.value) {
                                                        is io.kotest.core.test.TestResult.Error -> value.cause
                                                        is io.kotest.core.test.TestResult.Failure -> value.cause
                                                        else -> null
                                                    }
                                                    org.junit.jupiter.api.Assertions.assertFalse(entry.value.isErrorOrFailure) {
                                            """.trimIndent()
                                                    + "\"\"\"\$descriptor\n" +
                                                    "                        |\${cause?.stackTraceToString()}\"\"\".trimMargin()\n" +
                                                    """
                                                            }
                                                        }
                                                    }.let {
                                                        org.junit.jupiter.api.assertAll(it)
                                                    }
                                                    """.trimIndent() +
                                                    "\nprint(\"Total \${listener.tests.size}\")\n" +
                                                    "println(\" Failure \${listener.tests.count { it.value.isErrorOrFailure }}\")"

                                        ).addAnnotation(ClassName("org.junit.jupiter.api", "Test"))
                                            .build()


                                    )
                                        .build()
                                }.build()
                        ).build().apply {
                            targetDir.also { file ->
                                file.mkdirs()
                                writeTo(file)
                            }
                        }
                }
            }
        }
}

fun Project.setupAndroid() {
    project.extensions.getByName<LibraryExtension>("android").apply {
        namespace = "$group.${name.replace('-','.')}".also { logger.lifecycle("Setting Android namespace to $it") }
        compileSdk = 34
        defaultConfig {
            minSdk = 30
            testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        }


        dependencies {
            add("androidTestImplementation", "androidx.test:runner:${VcLibVersions.Android.testRunner}")
            add("androidTestImplementation", "androidx.test:core:${VcLibVersions.Android.testCore}")
            add("testImplementation", "org.junit.jupiter:junit-jupiter-api:${VcLibVersions.Android.junit}")
            add("testRuntimeOnly", "org.junit.jupiter:junit-jupiter-engine:${VcLibVersions.Android.junit}")
            add("androidTestImplementation", "org.junit.jupiter:junit-jupiter-api:${VcLibVersions.Android.junit}")
        }

        packaging {
            resources.excludes.add("/META-INF/{AL2.0,LGPL2.1}")
            resources.excludes.add("win32-x86-64/attach_hotspot_windows.dll")
            resources.excludes.add("win32-x86/attach_hotspot_windows.dll")
            resources.excludes.add("META-INF/versions/9/OSGI-INF/MANIFEST.MF")
            resources.excludes.add("META-INF/licenses/*")
        }

        testOptions {
            managedDevices {
                localDevices.create("pixel2api33") {
                    device = "Pixel 2"
                    apiLevel = 33
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}


class VcLibConventions : Plugin<Project> {
    override fun apply(target: Project) {
        if (target.rootProject != target) target.plugins.apply("com.android.library")
        target.plugins.apply("at.asitplus.gradle.conventions")
        if (target.rootProject != target) target.plugins.apply("de.mannodermaus.android-junit5")

        target.task("wireAndroidInstrumentedTests") {
            doFirst { target.wireAndroidInstrumentedTests() }
        }
        target.gradle.taskGraph.whenReady {
            target.wireAndroidInstrumentedTests()
            target.tasks.withType<KotlinCompilationTask<*>>().configureEach {
                compilerOptions {
                    freeCompilerArgs.add("-Xexpect-actual-classes")
                    optIn.add("kotlinx.cinterop.BetaInteropApi")
                }
            }
        }

    }
}

