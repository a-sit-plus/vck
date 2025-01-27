package at.asitplus.openid.dcql

import at.asitplus.data.validation.third_party.kotlin.requireIsNotEmpty
import kotlinx.serialization.Serializable
import kotlin.jvm.JvmInline

/**
 * A string identifying the particular claim. The value MUST be a non-empty string consisting of
 * alphanumeric, underscore (_) or hyphen (-) characters. Within the particular claims array, the
 * same id MUST NOT be present more than once.
 */
@Serializable
@JvmInline
value class DCQLClaimsQueryIdentifier(val string: String) {
    init {
        string.requireIsNotEmpty()
        require(string.all { it == '_' || it == '-' || it.isLetterOrDigit() }) {
            "Claims query identifier must only contain alphanumeric, underscore (_) or hyphen (-) characters."
        }
    }
}