plugins {
    `kotlin-dsl`
    idea
}
group = "at.asitplus.gradle"


dependencies {
    implementation("org.jetbrains.kotlin.multiplatform:org.jetbrains.kotlin.multiplatform.gradle.plugin:${libs.versions.kotlin.get()}")
    implementation(libs.agp)
    implementation(libs.asp)
    implementation(libs.tomlj)
}

repositories {
    maven {
        url = uri("https://raw.githubusercontent.com/a-sit-plus/gradle-conventions-plugin/mvn/repo")
        name = "aspConventions"
    } //KOTEST snapshot
    mavenCentral()
    google()
    gradlePluginPortal()
}

gradlePlugin {
    plugins.register("vclib-conventions") {
        id = "at.asitplus.gradle.vclib-conventions"
        implementationClass = "at.asitplus.gradle.VcLibConventions"
    }
}

kotlin {
    jvmToolchain(17)
}
