import org.jetbrains.kotlin.gradle.utils.loadPropertyFromResources

object AspVersions {

    private fun versionOf(dependency: String) = loadPropertyFromResources("versions.properties", dependency)

    val kotlin = versionOf("kotlin")
    val serialization = versionOf("serialization")
    val datetime = versionOf("datetime")
    val kotest = versionOf("kotest")
    val coroutines  = versionOf("coroutines")
    val napier = versionOf("napier")
    val nexus = versionOf("nexus")

    object Jvm {
        val target = versionOf("jvmTarget")
        val bouncycastle = versionOf("bouncycastle")
    }
}
