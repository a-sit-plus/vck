package at.asitplus.wallet.lib.data.rfc9110

import kotlin.jvm.JvmInline

/**
 *  5.1. Field Names
 *
 * A field name labels the corresponding field value as having the semantics defined by that name.
 * For example, the Date header field is defined in Section 6.6.1 as containing the origination
 * timestamp for the message in which it appears.
 *
 *   field-name     = token
 *
 * Field names are case-insensitive and ought to be registered within the "Hypertext Transfer
 * Protocol (HTTP) Field Name Registry"; see Section 16.3.1. The interpretation of a field does not
 * change between minor versions of the same major HTTP version, though the default behavior of a
 * recipient in the absence of such a field can change. Unless specified otherwise, fields are
 * defined for all versions of HTTP. In particular, the Host and Connection fields ought to be
 * recognized by all HTTP implementations whether or not they advertise conformance with HTTP/1.1.
 * New fields can be introduced without changing the protocol version if their defined semantics
 * allow them to be safely ignored by recipients that do not recognize them; see Section 16.3. A
 * proxy MUST forward unrecognized header fields unless the field name is listed in the Connection
 * header field (Section 7.6.1) or the proxy is specifically configured to block, or otherwise
 * transform, such fields. Other recipients SHOULD ignore unrecognized header and trailer fields.
 * Adhering to these requirements allows HTTP's functionality to be extended without updating or
 * removing deployed intermediaries.
 *
 *  16.3.1. Field Name Registry
 *
 * Field name:
 *     The requested field name. It MUST conform to the field-name syntax defined in
 *     Section 5.1, and it SHOULD be restricted to just letters, digits, and hyphen ('-')
 *     characters, with the first character being a letter.
 */
@JvmInline
value class HttpFieldName private constructor(private val delegate: HttpToken) {
    val value: String
        get() = delegate.value

    override fun toString() = value

    companion object {
        operator fun invoke(value: String) = HttpFieldName(
            delegate = HttpToken(value.lowercase().trim())
        )

        fun validate(value: String) {
            HttpToken.validate(value)
        }

        val Accept = HttpFieldName(Specification.ACCEPT)
        val Location = HttpFieldName(Specification.Location)
        val ContentType = HttpFieldName(Specification.ContentType)
    }

    object Specification {
        const val ACCEPT = "Accept"
        const val Location = "Location"
        const val ContentType = "Content-Type"
    }
}

