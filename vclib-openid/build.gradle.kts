import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.commonImplementationDependencies
import at.asitplus.gradle.commonIosExports
import at.asitplus.gradle.exportIosFramework

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

val dokkaOutputDir = "$buildDir/dokka"

tasks.dokkaHtmlPartial{
    dependsOn(":vclib-aries:transformIosMainCInteropDependenciesMetadataForIde")
    dependsOn(":vclib:transformIosMainCInteropDependenciesMetadataForIde")
    dokkaSourceSets {
        configureEach {
            sourceLink {
                localDirectory.set(file("src/$name/kotlin"))
                remoteUrl.set(
                    uri("https://github.com/a-sit-plus/kmm-vc-library/tree/main/${project.name}/src/$name/kotlin").toURL()
                )
                // Suffix which is used to append the line number to the URL. Use #L for GitHub
                remoteLineSuffix.set("#L")
            }
        }
    }
}

tasks.dokkaHtml {
    dependsOn(":vclib:transformIosMainCInteropDependenciesMetadataForIde") //task dependency bug workaround
    dependsOn(":vclib-aries:transformIosMainCInteropDependenciesMetadataForIde") //task dependency bug workaround
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

val signingTasks: TaskCollection<Sign> = tasks.withType<Sign>()
tasks.withType<PublishToMavenRepository>().configureEach {
    mustRunAfter(signingTasks)
}

exportIosFramework("VcLibOpenIdKmm", *commonIosExports(), project(":vclib"))
kotlin {

    sourceSets {
        val commonMain by getting {
            dependencies {
                commonImplementationDependencies()
                api(project(":vclib"))
            }
        }
        val commonTest by getting

        val iosMain by getting
        val iosSimulatorArm64Main by getting { dependsOn(iosMain) }
        val jvmMain by getting {
            dependencies {
                implementation(bouncycastle("bcprov"))
            }
        }
        val jvmTest by getting {
            dependencies {
                implementation("com.nimbusds:nimbus-jose-jwt:${VcLibVersions.Jvm.`jose-jwt`}")
                implementation("org.json:json:${VcLibVersions.Jvm.json}")
            }
        }
    }
}

repositories {
    mavenLocal()
    mavenCentral()
}


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
