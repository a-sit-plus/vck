import at.asitplus.gradle.*
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test

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


setupAndroid()

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
                api(project(":vck"))
                api(project(":openid-data-classes"))
                commonImplementationDependencies()
            }
        }

        commonTest {
            dependencies {
                implementation("at.asitplus.wallet:eupidcredential:${VcLibVersions.eupidcredential}")
                implementation("at.asitplus.wallet:mobiledrivinglicence:${VcLibVersions.mdl}")
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
            }
        }

        iosTest {
            dependencies {
                implementation("io.arrow-kt:arrow-core:1.2.4") //work around klib bug
            }
        }
    }
}

exportIosFramework(
    "VckOpenIdKmm",
    transitiveExports = true,
    project(":vck")
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
                name.set("VC-K OpenID")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model, with OpenId protocol implementations")
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
                artifactId = "vclib-openid"
                version = artifactVersion

                distributionManagement {
                    relocation {
                        // New artifact coordinates
                        artifactId = "vck-openid"
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

