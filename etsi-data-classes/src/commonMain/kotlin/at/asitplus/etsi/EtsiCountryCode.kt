package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class EtsiCountryCode(
    /** Uppercase country, regional or grouping code, including the special values UK, EL and EU (TS 119 602, 6.1.5). */
    val string: String
) {
    init {
        string.forEach {
            require(it in 'A'..'Z') {
                "Expected ETSI country code to consist of uppercase characters, but was $string"
            }
        }
    }
}