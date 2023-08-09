plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"

idea {
    project {
        jdkName = "11" //TODO use from ASP conventions plugin?
    }
}

dependencies {
    api("at.asitplus.gradle:conventions")
}

repositories {
    mavenCentral()
    gradlePluginPortal()
}
kotlin {
    jvmToolchain {
        (this as JavaToolchainSpec).languageVersion.set(JavaLanguageVersion.of(11/*TODO share*/))
    }
    /*compilerOptions {
        languageVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
        apiVersion.set(org.jetbrains.kotlin.gradle.dsl.KotlinVersion.KOTLIN_1_9)
    }*/
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
