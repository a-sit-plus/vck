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
                implementation(project.napier())
                api(serialization("json"))
                api(serialization("cbor"))
                api(datetime())
                api("com.ionspin.kotlin:bignum:${signumVersionCatalog.findVersion("bignum").get()}")
                api(kmmresult())
                api("at.asitplus.signum:indispensable:${VcLibVersions.signum}")
                api("at.asitplus.signum:indispensable-cosef:${VcLibVersions.signum}")
                api("at.asitplus.signum:indispensable-josef:${VcLibVersions.signum}")
                api("at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}")
                api("io.matthewnelson.encoding:core:${AspVersions.versions["encoding"]}")
                api("io.matthewnelson.encoding:base16:${AspVersions.versions["encoding"]}")
                api("io.matthewnelson.encoding:base64:${AspVersions.versions["encoding"]}")
            }
        }

        commonTest {
            dependencies {
            }
        }

        jvmMain {
            dependencies {
            }
        }

        jvmTest {
            dependencies {
            }
        }
    }
}

exportIosFramework(
    "DifDataClasses",
    static = false,
    *commonIosExports(),
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
                name.set("DIF Data Classes")
                description.set("Kotlin Multiplatform data classes for DIF")
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

