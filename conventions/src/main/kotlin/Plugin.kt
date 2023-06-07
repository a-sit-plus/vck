@file:Suppress("NOTHING_TO_INLINE")

package at.asitplus.gradle

import AspVersions
import io.github.gradlenexus.publishplugin.NexusPublishExtension
import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.Delete
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.jvm.toolchain.JavaLanguageVersion
import org.gradle.jvm.toolchain.JavaToolchainSpec
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.dsl.kotlinExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinMultiplatformPluginWrapper
import java.io.FileInputStream
import java.util.*

private inline fun Project.extraProps() {
    println("Adding support for storing extra project properties in local.properties")
    java.util.Properties().apply {
        kotlin.runCatching { load(java.io.FileInputStream(rootProject.file("local.properties"))) }
        forEach { (k, v) -> extra.set(k as String, v) }
    }
}

class AspConventions : Plugin<Project> {
    override fun apply(target: Project) {
        println("Adding nexus publish plugin")
        target.rootProject.plugins.apply("io.github.gradle-nexus.publish-plugin")

        target.extraProps()

        if (target == target.rootProject) {


            println("Adding google and maven central repositories")
            target.allprojects {
                repositories {
                    google()
                    mavenCentral()
                }
            }

            println("Adding clean task")
            target.tasks.register<Delete>("clean") {
                doFirst { println("Cleaning all build files") }

                delete(target.rootProject.buildDir)
                delete(target.layout.projectDirectory.dir("repo"))
                doLast { println("Clean done") }
            }

            println("Setting nexus publishing url to s01.oss.sonatype.org")
            target.extensions.getByType<NexusPublishExtension>().apply {
                repositories {
                    sonatype {
                        nexusUrl.set(java.net.URI("https://s01.oss.sonatype.org/service/local/"))
                        snapshotRepositoryUrl.set(java.net.URI("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
                    }
                }
            }


        }

        var isMultiplatform = false

        target.plugins.withType<KotlinMultiplatformPluginWrapper> {
            isMultiplatform = true
            println("Multiplatform project detected")
            println("Setting up Kotest multiplatform plugin")
            target.plugins.apply("io.kotest.multiplatform")

            target.extensions.getByType<KotlinMultiplatformExtension>().jvm {
                println("setting jsr305=strict")
                compilations.all {
                    kotlinOptions {
                        jvmTarget = AspVersions.Jvm.target
                        freeCompilerArgs = listOf(
                            "-Xjsr305=strict"
                        )
                    }
                }

                println("Configuring Kotest JVM runner")

                testRuns["test"].executionTask.configure {
                    useJUnitPlatform()
                }
            }

            target.afterEvaluate {


                val kmp = extensions.getByType<KotlinMultiplatformExtension>()

                println("Adding opt ins:")
                println("   * Serialization")
                println("   * Coroutines")
                println("   * kotlinx.time")
                println("   * RequiresOptIn")
                kmp.experimentalOptIns()

                @Suppress("UNUSED_VARIABLE")
                kmp.sourceSets {
                    val commonTest by getting {
                        dependencies {
                            addKotest()
                        }
                    }
                    val jvmTest by getting {
                        dependencies {
                            addKotestJvmRunner()
                        }
                    }
                }
            }
        }



        runCatching {

            val kotlin = target.kotlinExtension

            kotlin.apply {
                jvmToolchain {
                   languageVersion.set(JavaLanguageVersion.of(AspVersions.Jvm.target))
                }
            }
            if (target != target.rootProject) {


                if (!isMultiplatform) {
                    println("Assuming JVM-only Kotlin project")
                    target.afterEvaluate {
                        kotlin.apply {
                            sourceSets.getByName("test").dependencies {
                                addKotest("jvm")
                                addKotestJvmRunner()
                            }

                        }
                    }
                }
                println("Adding maven publish")
                target.plugins.apply("maven-publish")

                target.afterEvaluate {


                    println("Configuring Test output format")
                    target.tasks.withType<Test> {
                        if (name == "testReleaseUnitTest") return@withType
                        useJUnitPlatform()
                        filter {
                            isFailOnNoMatchingTests = false
                        }
                        testLogging {
                            showExceptions = true
                            showStandardStreams = true
                            events = setOf(
                                TestLogEvent.FAILED,
                                TestLogEvent.PASSED
                            )
                            exceptionFormat = TestExceptionFormat.FULL
                        }
                    }
                }
            }
        }.getOrElse {
            println("No Kotlin plugin detected")
        }

    }
}