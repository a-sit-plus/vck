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
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
