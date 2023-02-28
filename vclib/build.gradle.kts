import org.gradle.api.tasks.testing.logging.TestExceptionFormat
import org.gradle.api.tasks.testing.logging.TestLogEvent
import org.jetbrains.kotlin.gradle.plugin.mpp.apple.XCFrameworkConfig
import java.io.FileInputStream
import java.util.*

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization") version Versions.kotlin
    id("maven-publish")
    id("io.kotest.multiplatform") version Versions.kotest
    id("signing")
    id("org.jetbrains.dokka") version Versions.dokka
}

/* required for maven publication */
val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion

val dokkaOutputDir = "$buildDir/dokka"
tasks.dokkaHtml {
    outputDirectory.set(file(dokkaOutputDir))
}
val deleteDokkaOutputDir by tasks.register<Delete>("deleteDokkaOutputDirectory") {
    delete(dokkaOutputDir)
}
val javadocJar = tasks.register<Jar>("javadocJar") {
    dependsOn(deleteDokkaOutputDir, tasks.dokkaHtml)
    archiveClassifier.set("javadoc")
    from(dokkaOutputDir)
}

kotlin {
    val xcf = XCFrameworkConfig(project, "VcLibKMM")

    ios {
        binaries.framework {
            baseName = "VcLibKMM"
            embedBitcode("bitcode")
            xcf.add(this)
        }
    }

    iosSimulatorArm64 {
        binaries.framework {
            baseName = "VcLibKMM"
            embedBitcode("bitcode")
            xcf.add(this)
        }
    }

    jvm {
        compilations.all {
            kotlinOptions {
                jvmTarget = Versions.Jvm.target
                freeCompilerArgs = listOf(
                    "-Xjsr305=strict"
                )
            }
        }

        testRuns["test"].executionTask.configure {
            useJUnitPlatform()
        }
    }

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

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:${Versions.coroutines}")
                implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:${Versions.`serialization-json`}")
                implementation("com.benasher44:uuid:${Versions.uuid}")
                implementation("org.jetbrains.kotlinx:kotlinx-datetime:${Versions.datetime}")
                implementation("io.ktor:ktor-http:${Versions.ktor}")
                implementation("io.ktor:ktor-utils:${Versions.ktor}")
                implementation("com.squareup.okio:okio:${Versions.okio}")
                implementation("io.github.aakira:napier:${Versions.napier}")
                api("at.asitplus:kmmresult:${Versions.resultlib}")
                api("io.matthewnelson.kotlin-components:encoding-base16:${Versions.encoding}")
                api("io.matthewnelson.kotlin-components:encoding-base64:${Versions.encoding}")
            }
        }
        val commonTest by getting {
            dependencies {
                implementation("io.kotest:kotest-assertions-core:${Versions.kotest}")
                implementation("io.kotest:kotest-common:${Versions.kotest}")
                implementation("io.kotest:kotest-property:${Versions.kotest}")
                implementation("io.kotest:kotest-framework-engine:${Versions.kotest}")
                implementation("io.kotest:kotest-framework-datatest:${Versions.kotest}")
            }
        }



        val iosMain by getting
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }
        val jvmMain by getting {
            dependencies {
                implementation("org.bouncycastle:bcprov-jdk18on:${Versions.Jvm.bcprov}")
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation("com.nimbusds:nimbus-jose-jwt:${Versions.Jvm.`jose-jwt`}")
                implementation("io.kotest:kotest-runner-junit5-jvm:${Versions.kotest}")
                implementation("org.json:json:${Versions.Jvm.json}")
            }
        }
    }
}

tasks.withType<Test> {
    if(name == "testReleaseUnitTest") return@withType
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

Properties().apply {
    kotlin.runCatching { load(FileInputStream(project.rootProject.file("local.properties"))) }
    forEach { (k, v) -> extra.set(k as String, v) }
}

val gitLabPrivateToken: String? by extra
val gitLabProjectId: String by extra
val gitLabGroupId: String by extra

repositories {
    mavenLocal()
    if (System.getenv("CI_JOB_TOKEN") != null || gitLabPrivateToken != null) {
        maven {
            name = "gitlab"
            url = uri("https://gitlab.iaik.tugraz.at/api/v4/groups/$gitLabGroupId/-/packages/maven")
            if (gitLabPrivateToken != null) {
                credentials(HttpHeaderCredentials::class) {
                    name = "Private-Token"
                    value = gitLabPrivateToken
                }
            } else if (System.getenv("CI_JOB_TOKEN") != null) {
                credentials(HttpHeaderCredentials::class) {
                    name = "Job-Token"
                    value = System.getenv("CI_JOB_TOKEN")
                }
            }
            authentication {
                create<HttpHeaderAuthentication>("header")
            }
        }
    }
    mavenCentral()
}


publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KmmVcLib")
                description.set("Functional equivalent of kotlin.Result but with KMM goodness")
                url.set("https://github.com/a-sit-plus/kmm-vc-library")
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
                    connection.set("scm:git:git@github.com:a-sit-plus/kmm-vc-library.git")
                    developerConnection.set("scm:git:git@github.com:a-sit-plus/kmm-vc-library.git")
                    url.set("https://github.com/a-sit-plus/kmm-vc-library")
                }
            }
        }
    }
    repositories {
        mavenLocal()
        if (System.getenv("CI_JOB_TOKEN") != null) {
            maven {
                name = "gitlab"
                url = uri("https://gitlab.iaik.tugraz.at/api/v4/projects/$gitLabProjectId/packages/maven")
                credentials(HttpHeaderCredentials::class) {
                    name = "Job-Token"
                    value = System.getenv("CI_JOB_TOKEN")
                }
                authentication {
                    create<HttpHeaderAuthentication>("header")
                }
            }
        }
    }
}

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
