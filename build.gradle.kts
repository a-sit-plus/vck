import org.jetbrains.dokka.gradle.DokkaMultiModuleTask

plugins {
    id("at.asitplus.gradle.vclib-conventions")
    id("io.kotest.multiplatform") version libs.versions.kotest
}

//access dokka plugin from conventions plugin's classpath in root project → no need to specify version
apply(plugin = "org.jetbrains.dokka")
tasks.getByName("dokkaHtmlMultiModule") {
    (this as DokkaMultiModuleTask)
    outputDirectory.set(layout.buildDirectory.dir("dokka").get().asFile)
    includes.from("README.md")
    doLast {
        files(
            "vck-dark.png",
            "vck-light.png",
            "eu.svg",
        ).files.forEach { it.copyTo(File("build/dokka/${it.name}"), overwrite = true) }
    }
}

subprojects {
    // JVM runner
    tasks.withType<Test>().configureEach {
        useJUnitPlatform()
        systemProperty("kotest.framework.config.fqn",
            "KotestConfig")
    }

// JS runner(s)
    tasks.withType<org.jetbrains.kotlin.gradle.targets.js.testing.KotlinJsTest>()
        .configureEach {
            environment("KOTEST_FRAMEWORK_CONFIG_FQN",
                "KotestConfig")
        }

// Native runner(s)
    tasks.matching { it.name.endsWith("Test") && it is Exec }
        .configureEach {
            (this as Exec).environment("KOTEST_FRAMEWORK_CONFIG_FQN",
                "KotestConfig")
        }

}

val artifactVersion: String by extra
group = "at.asitplus.wallet"
version = artifactVersion
