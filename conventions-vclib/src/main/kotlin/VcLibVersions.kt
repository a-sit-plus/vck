import org.gradle.api.Project
import org.tomlj.Toml
import org.tomlj.TomlParseResult

class VcLibVersions(private val project: Project) {

    val versionCatalog: TomlParseResult by lazy {
        Toml.parse(
            project.rootProject.layout.projectDirectory.dir("gradle")
                .file("libs.versions.toml").asFile.inputStream()
        )
    }

    /**
     * Gets the version for the dependencies managed by shorthands. Can be overridden by `gradle/libs.versions.toml`
     */
    private fun versionOf(dependency: String) =
        versionCatalog.getTable("versions")?.getString(dependency) as String


    val uuid get() = versionOf("uuid")
    val signum get() = versionOf("signum")
    val supreme get() = versionOf("supreme")
    val jsonpath get() = versionOf("jsonpath")
    val obor get() = versionOf("obor")
    val eupidcredential get() = versionOf("eupid")
    val mdl get() = versionOf("mdl")

    val Jvm = JvmVersions()

    inner class JvmVersions {
        val json get() = versionOf("jvmJson")
        val `authlete-cbor` get() = versionOf("jvmCbor")
    }

    val Android = AndroidVersions()

    inner class AndroidVersions {
        val testRunner get() = versionOf("androidTestRunner")
        val testCore get() = versionOf("androidTestCore")
        val junit get() = versionOf("androidJunit")
    }
}
