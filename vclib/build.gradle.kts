import at.asitplus.gradle.*
import at.asitplus.gradle.at.asitplus.gradle.addTestExtensions

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
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
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {

        commonMain {
            dependencies {
                commonImplementationAndApiDependencies()
            }
        }

        commonTest {
            dependencies{
                addTestExtensions()
            }
        }
        jvmMain {
            dependencies {
                implementation(bouncycastle("bcpkix"))
            }
        }
        jvmTest {
            dependencies {
                implementation("com.nimbusds:nimbus-jose-jwt:${VcLibVersions.Jvm.`jose-jwt`}")
                implementation("org.json:json:${VcLibVersions.Jvm.json}")
            }
        }
    }
}

exportXCFramework("VcLibKmm", transitiveExports = false, additionalExports = commonIosExports())

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
