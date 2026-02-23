package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Base class for the subject of a [VerifiableCredential], see subclasses of this class, e.g., a concrete credential
 * implementation
 */
@Deprecated(
    message = "CredentialSubject is deprecated. Use JsonElement for credential subjects instead.",
    replaceWith = ReplaceWith("JsonElement", "kotlinx.serialization.json.JsonElement"),
    level = DeprecationLevel.WARNING
)
@Serializable
abstract class CredentialSubject {
    /**
     * This is the subjectId of the credential
     */
    @SerialName("id")
    abstract val id: String

}