package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * ISO 3166-1 alpha-2 codes
 */
@Serializable
@JvmInline
value class Iso3166Alpha2Code(val string: String) {
    init {
        require(string.length == 2) {
            "Expected ISO 3166-1 alpha-2 code to consist of exactly 2 characters, but was $string"
        }
        string.forEach {
            require(it in 'A'..'Z') {
                "Expected ISO 3166-1 alpha-2 code to consist of uppercase characters, but was $string"
            }
        }
    }
}

