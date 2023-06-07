import org.jetbrains.kotlin.gradle.utils.loadPropertyFromResources


object AspVersions {
    @JvmStatic
    private fun versionOf(dependency: String) = loadPropertyFromResources("versions.properties", dependency)

    @JvmStatic
    val kotlin = versionOf("kotlin")

    @JvmStatic
    val serialization = versionOf("serialization")

    @JvmStatic
    val datetime = versionOf("datetime")

    @JvmStatic
    val kotest = versionOf("kotest")

    @JvmStatic
    val ktor = versionOf("ktor")

    @JvmStatic
    val coroutines = versionOf("coroutines")

    @JvmStatic
    val napier = versionOf("napier")

    @JvmStatic
    val nexus = versionOf("nexus")

    object Jvm {
        @JvmStatic
        val target = versionOf("jvmTarget")

        @JvmStatic
        val bouncycastle = versionOf("bouncycastle")
    }

    @JvmStatic
    val jvm = Jvm //groovy workaround
}
