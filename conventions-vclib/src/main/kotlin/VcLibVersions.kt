import org.gradle.api.Project
import java.util.*


object VcLibVersions {

    private val versions by lazy {
        javaClass.classLoader!!.getResourceAsStream("vcLibVersions.properties").use { Properties().apply { load(it) } }
    }

    private fun versionOf(dependency: String) = versions[dependency] as String

    val uuid get() = versionOf("uuid")
    val kmpcrypto get() = versionOf("kmpCrypto")
    val jsonpath get() = versionOf("jsonpath")
    val eupidcredential get() = versionOf("eupid")
    val mdl get() = versionOf("mdl")

    object Jvm {
        val json get() = versionOf("jvm.json")
    }
}
