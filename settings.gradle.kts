pluginManagement {
    includeBuild("conventions-vclib")
    repositories {
        maven("https://maven.pkg.jetbrains.space/kotlin/p/dokka/dev")
        google()
        gradlePluginPortal()
        mavenCentral()
    }
}

rootProject.name = "vclibrary"
include(":vclib")
include(":vclib-aries")
include(":vclib-openid")

includeBuild("kmp-crypto") {
    dependencySubstitution {
        substitute(module("at.asitplus.crypto:datatypes")).using(project(":datatypes"))
        substitute(module("at.asitplus.crypto:datatypes-jws")).using(project(":datatypes-jws"))
        substitute(module("at.asitplus.crypto:datatypes-cose")).using(project(":datatypes-cose"))
    }
}

startParameter.excludedTaskNames+="transformNativeMainCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
startParameter.excludedTaskNames+="transformAppleMainCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
startParameter.excludedTaskNames+="transformIosMainCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
startParameter.excludedTaskNames+="transformNativeTestCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
startParameter.excludedTaskNames+="transformAppleTestCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
startParameter.excludedTaskNames+="transformIosTestCInteropDependenciesMetadataForIde" //disable broken import on non-macOS
