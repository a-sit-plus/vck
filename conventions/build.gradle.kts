plugins {
    `kotlin-dsl`
}
dependencies {
    implementation("org.jetbrains.kotlin:kotlin-gradle-plugin:1.8.0")
}

repositories {
    mavenCentral()
}
tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile>().configureEach {
    kotlinOptions {
        jvmTarget = "11"
    }
}

gradlePlugin {
    // Add fake plugin, if you don't have any
    plugins.register("asp-conventions") {
        id = "at.asitplus.gradle.conventions"
        implementationClass = "AspConventions"
    }
    // Or provide your implemented plugins
}