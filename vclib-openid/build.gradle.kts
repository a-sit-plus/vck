import at.asitplus.gradle.*

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")
    id("at.asitplus.gradle.vclib-conventions")
    id("org.jetbrains.dokka")
    id("signing")
}

/* required for maven publication */
val artifactVersion: String by extra
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
                api(project(":vclib"))
                commonImplementationDependencies()
            }
        }

        commonTest {
            dependencies {
                implementation("at.asitplus.wallet:eupidcredential:1.0.0")
            }
        }

        jvmMain {
            dependencies {
                implementation(bouncycastle("bcprov"))
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

exportIosFramework("VcLibOpenIdKmm", *commonIosExports(), project(":vclib"))

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/kmm-vc-library/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KmmVcLibOpenId")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model, with OpenId protocol implementations")
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

