package at.asitplus.openid.dcql

import at.asitplus.data.validation.third_party.kotlin.requireIsNotEmpty
import at.asitplus.rfc5234ABNF.Rfc5234ABNFCore.isAlpha
import at.asitplus.rfc5234ABNF.Rfc5234ABNFCore.isDigit
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * OID4VP 1.0, 6.1: id: REQUIRED. A string identifying the Credential in the response and, if provided, the
 * constraints in credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_), or
 * hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more than once.
 */
@Serializable
@JvmInline
value class DCQLCredentialQueryIdentifier(val string: String) {
    init {
        string.requireIsNotEmpty()
        // "alphanumeric" as the ASCII letters and digits, ALPHA and DIGIT of RFC 5234, B.1, not every Unicode letter
        require(string.all { it == '_' || it == '-' || it.isAlpha() || it.isDigit() }) {
            "Credential query identifier must only contain alphanumeric, underscore (_) or hyphen (-) characters."
        }
    }
}

