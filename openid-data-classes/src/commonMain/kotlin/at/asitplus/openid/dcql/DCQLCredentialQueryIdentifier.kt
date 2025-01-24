package at.asitplus.openid.dcql

import at.asitplus.data.validation.third_party.kotlin.requireIsNotEmpty
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * A string identifying the Credential in the response and, if provided, the constraints in
 * credential_sets. The value MUST be a non-empty string consisting of alphanumeric, underscore (_)
 * or hyphen (-) characters. Within the Authorization Request, the same id MUST NOT be present more
 * than once.
 */
@Serializable
@JvmInline
value class DCQLCredentialQueryIdentifier(val string: String) {
    init {
        string.requireIsNotEmpty()
        require(string.all {
            it == '_' || it == '-' || it.isLetterOrDigit()
        }) {
            "Credential query identifier must only contain alphanumeric, underscore (_) or hyphen (-) characters."
        }
    }
}

