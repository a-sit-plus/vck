import java.util.*

object VcLibVersions {

    private val versions by lazy {
        javaClass.classLoader!!.getResourceAsStream("vcLibVersions.properties").use { Properties().apply { load(it) } }
    }

    private fun versionOf(dependency: String) = versions[dependency] as String

    val uuid get() = versionOf("uuid")
    val signum get() = versionOf("signum")
    val supreme get() = versionOf("supreme")
    val jsonpath get() = versionOf("jsonpath")
    val obor get() = versionOf("obor")
    val eupidcredential get() = versionOf("eupid")
    val mdl get() = versionOf("mdl")

    object Jvm {
        val json get() = versionOf("jvm.json")
        val `authlete-cbor` get() = versionOf("jvm.cbor")
    }

    object Android {
        val testRunner get() = versionOf("android.testRunner")
        val testCore get() = versionOf("android.testCore")
        val junit get() = versionOf("android.junit")
    }
}
