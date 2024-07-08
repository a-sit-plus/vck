import java.util.*

object VcLibVersions {

    private val versions by lazy {
        javaClass.classLoader!!.getResourceAsStream("vcLibVersions.properties").use { Properties().apply { load(it) } }
    }

    private fun versionOf(dependency: String) = versions[dependency] as String


    const val uuid = "0.8.1"
    val kmpcrypto get() = versionOf("kmpCrypto")
    const val jsonpath = "2.0.0"

    object Jvm {
        const val json = "20230618"
    }
}
