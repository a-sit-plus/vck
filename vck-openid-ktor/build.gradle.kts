import at.asitplus.gradle.VcLibVersions
import at.asitplus.gradle.commonImplementationDependencies
import at.asitplus.gradle.envExtra
import at.asitplus.gradle.exportXCFramework
import at.asitplus.gradle.hasAndroidSdk
import at.asitplus.gradle.kotest
import at.asitplus.gradle.ktor
import at.asitplus.gradle.setupDokka
import at.asitplus.gradle.vckAndroid

plugins {
    id("at.asitplus.gradle.vclib-conventions")
}

/* required for maven publication */
val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion


val disableAppleTargets by envExtra
kotlin {
    jvm()
    vckAndroid()
    if ("true" != disableAppleTargets) {
        iosArm64()
        iosSimulatorArm64()

    }
    sourceSets {

        commonMain {
            dependencies {
                api(project(":vck-openid"))
                implementation(ktor("client-cio"))
                implementation(ktor("client-logging"))
                implementation(ktor("client-content-negotiation"))
                implementation(ktor("serialization-kotlinx-json"))
                commonImplementationDependencies()
            }
        }

        if (project.hasAndroidSdk()) {
            androidMain {
                dependencies {
                    implementation(ktor("client-android"))
                }
            }
        }

        commonTest {
            dependencies {
                implementation("at.asitplus.wallet:eupidcredential:${VcLibVersions.eupidcredential}")
                implementation("at.asitplus.wallet:mobiledrivinglicence:${VcLibVersions.mdl}")
                implementation(ktor("client-mock"))
                implementation(kotest("assertions-core"))
            }
        }

        iosTest {
            dependencies {
                implementation(ktor("client-darwin"))
            }
        }
    }
}

if ("true" != disableAppleTargets) exportXCFramework(
    "VckOpenIdKtorKmm",
    transitiveExports = true,
    static = false,
    project(":vck-openid")
)

val javadocJar = setupDokka(baseUrl = "https://github.com/a-sit-plus/vck/tree/main/")

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("VC-K OpenID with ktor")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model, with OpenId protocol implementations and ktor client")
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

signing {
    val signingKeyId: String? by project
    val signingKey: String? by project
    val signingPassword: String? by project
    useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
    sign(publishing.publications)
}

