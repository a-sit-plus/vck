import at.asitplus.gradle.*
import at.asitplus.gradle.at.asitplus.gradle.addTestExtensions
import com.android.build.api.dsl.KotlinMultiplatformAndroidLibraryTarget

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("com.android.kotlin.multiplatform.library")
    id("de.infix.testBalloon")
    id("at.asitplus.gradle.vclib-conventions")
    id("org.jetbrains.dokka")
    id("signing")
}

/* required for maven publication */
val artifactVersion = extra["artifactVersion"] as String
group = "at.asitplus.wallet"
version = artifactVersion

kotlin {
    jvm()
    targets.withType<KotlinMultiplatformAndroidLibraryTarget>().configureEach {
        namespace = "at.asitplus.wallet.vclib"
        withDeviceTestBuilder {
            sourceSetTreeName = "test"
        }.configure {
            instrumentationRunnerArguments["timeout_msec"] = "2400000"
            instrumentationRunnerArguments["TESTBALLOON_REPORTING_PATH_LIMIT"] = "400"
            managedDevices {
                localDevices {
                    create("pixelAVD").apply {
                        device = "Pixel 4"
                        apiLevel = 35
                        systemImageSource = "aosp-atd"
                    }
                }
            }
        }
        packaging.resources.excludes += listOf(
            "/META-INF/{AL2.0,LGPL2.1}",
            "META-INF/licenses/*",
            "META-INF/LICENSE.*",
            "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
        )
    }
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {

        commonMain {
            dependencies {
                commonImplementationAndApiDependencies()
                api(libs.okio)
                api(libs.encoding.base16)
                api(libs.encoding.base64)
            }
        }

        commonTest {
            dependencies{
                addTestExtensions()
            }
        }
        androidJvmMain {
            dependencies {
                implementation(bouncycastle("bcpkix"))
            }
        }
        jvmTest {
            dependencies {
                implementation(libs.nimbus.jose.jwt)
                implementation(libs.json)
            }
        }
    }
}

exportXCFramework(
    "VcLibKmm",
    transitiveExports = false,
    additionalExports = arrayOf(datetime(), kmmresult(), libs.encoding.base16.get()),
)

val javadocJar = setupDokka(baseUrl = "https://github.com/a-sit-plus/vck/tree/release-pupilid/")

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KmmVcLib")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model")
                url.set("https://github.com/a-sit-plus/vck/tree/release-pupilid")
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
                    url.set("https://github.com/a-sit-plus/vck")
                }
            }
        }
    }
    repositories {
        mavenLocal {
            signing.isRequired = false
        }
    }
}

signing {
    val signingKeyId = project.findProperty("signingKeyId") as String?
    val signingKey = project.findProperty("signingKey") as String?
    val signingPassword = project.findProperty("signingPassword") as String?
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}
