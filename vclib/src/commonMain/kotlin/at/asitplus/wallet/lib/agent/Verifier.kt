package at.asitplus.wallet.lib.agent

import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed


/**
 * Summarizes operations for a Verifier in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can verify credentials and presentations.
 */
interface Verifier {

    /**
     * Set the revocation list to use for validating VCs (from [Issuer.issueRevocationListCredential])
     */
    fun setRevocationList(it: String): Boolean

    /**
     * Verifies a presentation of some credentials that a holder issued with that [challenge] we sent before.
     */
    fun verifyPresentation(it: String, challenge: String): VerifyPresentationResult

    /**
     * Verifies if a presentation contains all required [attributeNames].
     */
    fun verifyPresentationContainsAttributes(it: VerifiablePresentationParsed, attributeNames: List<String>): Boolean

    /**
     * Parse a single VC, checks if subject matches
     */
    fun verifyVcJws(it: String): VerifyCredentialResult

    sealed class VerifyPresentationResult {
        data class Success(val vp: VerifiablePresentationParsed) : VerifyPresentationResult()
        data class InvalidStructure(val input: String) : VerifyPresentationResult()
        data class NotVerified(val input: String, val challenge: String) : VerifyPresentationResult()
    }

    sealed class VerifyCredentialResult {
        data class Success(val jws: VerifiableCredentialJws): VerifyCredentialResult()
        data class Revoked(val input: String, val jws: VerifiableCredentialJws): VerifyCredentialResult()
        data class InvalidStructure(val input: String): VerifyCredentialResult()
    }

}
