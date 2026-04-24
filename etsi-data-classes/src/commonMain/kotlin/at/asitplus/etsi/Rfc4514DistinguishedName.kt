package at.asitplus.etsi

import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * The string representation of an X.501 Distinguished Name, decoded to a string as specified in RFC4514
 */
@Serializable
@JvmInline
value class Rfc4514DistinguishedName(
    val string: String
) {
    init {
        // TODO: implement proper grammar verification or decoding?
    }
}