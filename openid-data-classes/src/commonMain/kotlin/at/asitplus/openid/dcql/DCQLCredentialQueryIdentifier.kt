package at.asitplus.openid.dcql

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
        validate()
    }

    fun validate() {
        if(string.isEmpty()) {
            throw IllegalArgumentException("Value must not be the empty string.")
        }
        string.forEach {
            if(it != '_' && it != '-' && !it.isLetterOrDigit()) {
                throw IllegalArgumentException("Value must only consist of alphanumeric, underscore (_) or hyphen (-) characters.")
            }
        }
    }
}

