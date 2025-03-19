import at.asitplus.gradle.exportXCFramework
import at.asitplus.gradle.ktor
import at.asitplus.gradle.napier
import at.asitplus.gradle.setupAndroid
import at.asitplus.gradle.setupDokka
import org.jetbrains.kotlin.gradle.ExperimentalKotlinGradlePluginApi
import org.jetbrains.kotlin.gradle.plugin.KotlinSourceSetTree.Companion.test

plugins {
    id("com.android.library")
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
    androidTarget {
        @OptIn(ExperimentalKotlinGradlePluginApi::class)
        instrumentedTestVariant.sourceSetTree.set(test)
    }
    iosArm64()
    iosSimulatorArm64()
    iosX64()
    sourceSets {

        commonMain {
            dependencies {
                implementation(project.napier())
                implementation(project.ktor("http"))
                api(project(":dif-data-classes"))
                api(project(":openid-data-classes"))
                api("com.benasher44:uuid:${VcLibVersions.uuid}")
                api("at.asitplus.signum:indispensable-cosef:${VcLibVersions.signum}")
                api("at.asitplus.signum:indispensable-josef:${VcLibVersions.signum}")
                api("at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}")
            }
        }
    }
}


setupAndroid()

exportXCFramework(
    "RqesDataClasses",
    transitiveExports = true,
    static = false,
    "at.asitplus.signum:indispensable-cosef:${VcLibVersions.signum}",
    "at.asitplus.signum:indispensable-josef:${VcLibVersions.signum}",
    "at.asitplus:jsonpath4k:${VcLibVersions.jsonpath}",
    "com.benasher44:uuid:${VcLibVersions.uuid}"
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
                name.set("RQES Data Classes")
                description.set("Kotlin Multiplatform data classes for RQES")
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
                    developer {
                        id.set("n0900")
                        name.set("Simon Mueller")
                        email.set("simon.mueller@a-sit.at")
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

