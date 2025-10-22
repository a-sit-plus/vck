import at.asitplus.gradle.*
import org.gradle.kotlin.dsl.withType
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jetbrains.kotlin.konan.target.HostManager

plugins {
    id("at.asitplus.gradle.vclib-conventions")
}

/* required for maven publication */
val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion


vckAndroid()
kotlin {
    jvm()
    if (HostManager.hostIsMac) {
        iosArm64()
        iosSimulatorArm64()
        iosX64()
    }
    sourceSets {

        commonMain {
            dependencies {
                api(project(":dif-data-classes"))
                api(project(":csc-data-classes"))
                api(ktor("http"))
                implementation(napier())
                commonImplementationAndApiDependencies()
            }
        }
    }
}

if (HostManager.hostIsMac) exportXCFramework(
    "OpenIdDataClasses",
    transitiveExports = true,
    static = false,
    project(":dif-data-classes"),
            project(":csc-data-classes")
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
                name.set("OpenID Data Classes")
                description.set("Kotlin Multiplatform data classes for OpenId")
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

