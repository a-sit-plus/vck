package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

@Serializable
@JvmInline
value class EtsiCountryCode(val string: String) {
    init {
        string.forEach {
            require(it in 'A'..'Z') {
                "Expected ETSI country code to consist of uppercase characters, but was $string"
            }
        }
    }
}