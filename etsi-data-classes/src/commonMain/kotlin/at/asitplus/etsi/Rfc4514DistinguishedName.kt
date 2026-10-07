package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * The string representation of an X.501 Distinguished Name, decoded to a string as specified in RFC4514
 */
@Serializable
@JvmInline
value class Rfc4514DistinguishedName(
    /** RFC 4514 string representation of an X.501 distinguished name (TS 119 602, 6.6.3.2). */
    val string: String
) {
    init {
        // TODO: implement proper grammar verification or decoding?
    }
}