package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Base class for the subject of a [VerifiableCredential], see subclasses of this class, e.g. [AtomicAttributeCredential].
 */
@Serializable
open class CredentialSubject(
    /**
     * This is the subjectId of the credential
     */
    @SerialName("id")
    val id: String,
)