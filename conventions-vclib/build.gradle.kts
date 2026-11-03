plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"

dependencies {
    implementation("org.jetbrains.kotlin.multiplatform:org.jetbrains.kotlin.multiplatform.gradle.plugin:${libs.versions.kotlin.get()}")
    implementation(libs.asp)
    implementation(libs.agp)
}

repositories {
    maven("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
    mavenCentral()
    google()
    gradlePluginPortal()
}

kotlin {
    jvmToolchain(17)
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}
