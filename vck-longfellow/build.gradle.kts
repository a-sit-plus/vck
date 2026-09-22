import at.asitplus.gradle.VcLibVersions
import at.asitplus.gradle.commonImplementationAndApiDependencies
import at.asitplus.gradle.envExtra
import at.asitplus.gradle.exportXCFramework
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
                api(project(":vck"))
                implementation("org.multipaz:multipaz:${VcLibVersions.multipaz}")
                implementation("org.multipaz:multipaz-longfellow:${VcLibVersions.multipaz}")
                commonImplementationAndApiDependencies()
            }
        }
    }
}

if ("true" != disableAppleTargets) exportXCFramework(
    "VckLongfellowKmm",
    transitiveExports = true,
    static = false,
    project(":vck"),
)

val javadocJar = setupDokka(baseUrl = "https://github.com/a-sit-plus/vck/tree/main/")

publishing {
    publications {
        withType<MavenPublication> {
            if (this.name != "relocation") artifact(javadocJar)
            pom {
                name.set("VC-K Longfellow")
                description.set("Kotlin Multiplatform library implementing longfellow-zk backend for VCK")
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