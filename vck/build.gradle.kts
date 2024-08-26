import at.asitplus.gradle.*
import com.squareup.kotlinpoet.AnnotationSpec
import com.squareup.kotlinpoet.ClassName
import com.squareup.kotlinpoet.FileSpec
import com.squareup.kotlinpoet.TypeSpec
import at.asitplus.gradle.commonImplementationAndApiDependencies
import at.asitplus.gradle.commonIosExports
import at.asitplus.gradle.exportIosFramework
import at.asitplus.gradle.setupDokka
import com.android.build.gradle.internal.utils.getOrderedFileTree
import com.squareup.kotlinpoet.FunSpec
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test
import java.io.FileInputStream
import java.util.regex.Pattern

plugins {
    id("com.android.library")
    kotlin("multiplatform")
    kotlin("plugin.serialization")

    id("at.asitplus.gradle.vclib-conventions")
    id("org.jetbrains.dokka")
    id("signing")

    id("de.mannodermaus.android-junit5") version "1.11.0.0"

}

/* required for maven publication */
val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

buildscript {
    dependencies {
        classpath(libs.kotlinpoet)
    }
}

wireAndroidInstrumentedTests()

task("wireAndroidInstrumentedTests") {
    doFirst { wireAndroidInstrumentedTests() }
}

kotlin {

    jvm()
    androidTarget {
        publishLibraryVariants("release")
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(test)
    }
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {
        commonMain {
            dependencies {
                implementation("at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}") {
                    exclude("org.jetbrains.kotlin", "kotlin-reflect")
                }
                api(project(":dif-data-classes"))
                commonImplementationAndApiDependencies()
            }
        }


        jvmMain {
            dependencies {
                implementation(signum.bcpkix.jdk18on)
            }
        }
        jvmTest {
            dependencies {
                implementation(signum.jose)
                implementation("org.json:json:${VcLibVersions.Jvm.json}")
                implementation("com.authlete:cbor:${VcLibVersions.Jvm.`authlete-cbor`}")
            }
        }
    }
}


android {
    namespace = "at.asitplus.wallet.vck"
    compileSdk = 34
    defaultConfig {
        minSdk = 33
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }


    dependencies {
        androidTestImplementation(libs.runner)
        androidTestImplementation(libs.androidx.testcore)
        //  androidTestImplementation(libs.rules)
        testImplementation("org.junit.jupiter:junit-jupiter-api:5.11.0")
        testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.11.0")
        androidTestImplementation("org.junit.jupiter:junit-jupiter-api:5.11.0")
        //androidTestImplementation("androidx.fragment:fragment-testing:1.8.2")
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
            localDevices {
                create("pixel2api33") {
                    device = "Pixel 2"
                    apiLevel = 33
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}

exportIosFramework(
    name = "VckKmm",
    static = false,
    *commonIosExports(), project(":dif-data-classes")
)

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/vck/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("VC-K")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model")
                url.set("https://github.com/a-sit-plus/vck")
                licenses {
                    license {
                        name.set("The Apache License, Version 2.0")
                        url.set("http://www.apache.org/licenses/LICENSE-2.0.txt")
                    }
                }
                developers {
                    developer {
                        id.set("JesusMcCloud")
                        name.set("Bernd Prünster")
                        email.set("bernd.pruenster@a-sit.at")
                    }
                    developer {
                        id.set("nodh")
                        name.set("Christian Kollmann")
                        email.set("christian.kollmann@a-sit.at")
                    }
                }
                scm {
                    connection.set("scm:git:git@github.com:a-sit-plus/vck.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/vck.git")
                    url.set("https://github.com/a-sit-plus/vck")
                }
            }
        }
        //REMOVE ME AFTER REBRANDED ARTIFACT HAS BEEN PUBLISHED
        create<MavenPublication>("relocation") {
            pom {
                // Old artifact coordinates
                artifactId = "vclib"
                version = artifactVersion

                distributionManagement {
                    relocation {
                        // New artifact coordinates
                        artifactId = "vck"
                        version = artifactVersion
                        message = " artifactId have been changed"
                    }
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
        maven {
            url = uri(layout.projectDirectory.dir("..").dir("repo"))
            name = "local"
            signing.isRequired = false
        }
    }
}


fun wireAndroidInstrumentedTests() {
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

repositories {
    maven(url = uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
    mavenCentral()
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
