package at.asitplus.openid.dcql

import at.asitplus.data.validation.third_party.kotlin.requireIsNotEmpty
import at.asitplus.rfc5234ABNF.Rfc5234ABNFCore.isAlpha
import at.asitplus.rfc5234ABNF.Rfc5234ABNFCore.isDigit
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * OID4VP 1.0, 6.3: id: […] A string identifying the particular claim. The value MUST be a non-empty string consisting
 * of alphanumeric, underscore (_), or hyphen (-) characters. Within the particular claims array, the same id MUST NOT
 * be present more than once.
 */
@Serializable
@JvmInline
value class DCQLClaimsQueryIdentifier(val string: String) {
    init {
        string.requireIsNotEmpty()
        // "alphanumeric" as the ASCII letters and digits, ALPHA and DIGIT of RFC 5234, B.1, not every Unicode letter
        require(string.all { it == '_' || it == '-' || it.isAlpha() || it.isDigit() }) {
            "Claims query identifier must only contain alphanumeric, underscore (_) or hyphen (-) characters."
        }
    }
}