
import at.asitplus.gradle.bouncycastle
import at.asitplus.gradle.commonImplementationAndApiDependencies
import at.asitplus.gradle.commonIosExports
import at.asitplus.gradle.exportIosFramework
import at.asitplus.gradle.setupDokka
import com.strumenta.antlrkotlin.gradle.AntlrKotlinTask
import org.jetbrains.kotlin.gradle.dsl.KotlinCompile

plugins {
    kotlin("multiplatform")
    kotlin("plugin.serialization")

    id("at.asitplus.gradle.vclib-conventions")
    id("org.jetbrains.dokka")
    id("signing")

    id("com.strumenta.antlr-kotlin") version "1.0.0-RC2"
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
            kotlin {
                srcDir(layout.buildDirectory.dir("generatedAntlr"))
            }
            dependencies {
                commonImplementationAndApiDependencies()
                implementation("com.strumenta:antlr-kotlin-runtime:1.0.0-RC2")
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

exportIosFramework("VcLibKmm", *commonIosExports())

val javadocJar = setupDokka(
    baseUrl = "https://github.com/a-sit-plus/kmm-vc-library/tree/main/",
    multiModuleDoc = true
)

publishing {
    publications {
        withType<MavenPublication> {
            artifact(javadocJar)
            pom {
                name.set("KmmVcLib")
                description.set("Kotlin Multiplatform library implementing the W3C VC Data Model")
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

val generateKotlinGrammarSource = tasks.register<AntlrKotlinTask>("generateKotlinGrammarSource") {
    dependsOn("cleanGenerateKotlinGrammarSource")

    // ANTLR .g4 files are under {example-project}/antlr
    // Only include *.g4 files. This allows tools (e.g., IDE plugins)
    // to generate temporary files inside the base path
    source = fileTree(layout.projectDirectory) {
        include("**/*.g4")
    }

    // We want the generated source files to have this package name
    val pkgName = "at.asitplus.parser.generated"
    packageName = pkgName

    // We want visitors alongside listeners.
    // The Kotlin target language is implicit, as is the file encoding (UTF-8)
    arguments = listOf("-visitor")

    // Generated files are outputted inside build/generatedAntlr/{package-name}
    val outDir = "generatedAntlr/${pkgName.replace(".", "/")}"
    outputDirectory = layout.buildDirectory.dir(outDir).get().asFile
}

tasks.withType<KotlinCompile<*>> {
    dependsOn(generateKotlinGrammarSource)
}
tasks.withType<AntlrKotlinTask> {
    dependsOn(tasks.named("jvmProcessResources"))
}