import org.gradle.api.Plugin
import org.gradle.api.Project
import org.gradle.api.tasks.testing.Test
import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.gradle.kotlin.dsl.*
import org.jetbrains.kotlin.gradle.dsl.KotlinMultiplatformExtension
import org.jetbrains.kotlin.gradle.dsl.kotlinExtension
import org.jetbrains.kotlin.gradle.plugin.KotlinMultiplatformPluginWrapper

class AspConventions : Plugin<Project> {
    override fun apply(target: Project) {
        target.rootProject.plugins.apply("io.github.gradle-nexus.publish-plugin")
        target.plugins.withType<KotlinMultiplatformPluginWrapper> {
            println("Multiplatform project detected")
            println("Setting up Kotest multiplatform plugin")
            target.plugins.apply("io.kotest.multiplatform")
            target.afterEvaluate {


                val kmp = target.extensions.getByType<KotlinMultiplatformExtension>()

                println("Adding Kotest libraries:")
                println("   * Assertions")
                println("   * Property-based testing")
                println("   * Datatest")
                kmp.sourceSets {
                    val commonTest by getting {
                        dependencies {
                            commonTestDependencies()
                        }
                    }
                    val jvmTest by getting {
                        dependencies {
                            implementation("io.kotest:kotest-runner-junit5-jvm:${Versions.kotest}")
                        }
                    }
                }

                println("Configuring Kotest JVM runner")
                kmp.jvm {
                    testRuns["test"].executionTask.configure {
                        useJUnitPlatform()
                    }
                }
            }
        }
        runCatching {
            target.kotlinExtension
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

    }
}