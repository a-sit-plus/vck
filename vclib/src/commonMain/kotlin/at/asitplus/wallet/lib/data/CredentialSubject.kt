package at.asitplus.wallet.lib.data

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Base class for the subject of a [VerifiableCredential], see subclasses of this class, e.g. [AtomicAttribute2023].
 */
@Serializable
abstract class CredentialSubject {
    /**
     * This is the subjectId of the credential
     */
    @SerialName("id")
    abstract val id: String

    /**
     * Return list of claims, to process further when building selective disclosure items
     */
    abstract fun getClaims(): List<Claim>

    data class Claim(val name: String, val value: String)
}