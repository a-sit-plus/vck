package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.jwkId
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.ReconstructedSdJwtClaims
import at.asitplus.wallet.lib.jws.SdJwtSigned


/**
 * Summarizes operations for a Verifier in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can verify credentials and presentations.
 */
interface Verifier {

    /**
     * The public key for this agent, i.e. the one used to validate the audience of a VP against
     */
    val keyMaterial: KeyMaterial

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
        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            @Deprecated("Renamed to verifiableCredentialSdJwt", replaceWith = ReplaceWith("verifiableCredentialSdJwt"))
            val sdJwt: VerifiableCredentialSdJwt,
            val reconstructed: ReconstructedSdJwtClaims,
            val disclosures: Collection<SelectiveDisclosureItem>,
            val isRevoked: Boolean
        ) : VerifyPresentationResult()

        data class SuccessIso(val documents: Collection<IsoDocumentParsed>) : VerifyPresentationResult()
        data class InvalidStructure(val input: String) : VerifyPresentationResult()
        data class NotVerified(val input: String, val challenge: String) : VerifyPresentationResult()
    }

    sealed class VerifyCredentialResult {
        data class SuccessJwt(val jws: VerifiableCredentialJws) : VerifyCredentialResult()
        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            @Deprecated("Renamed to verifiableCredentialSdJwt", replaceWith = ReplaceWith("verifiableCredentialSdJwt"))
            val sdJwt: VerifiableCredentialSdJwt,
            val reconstructed: ReconstructedSdJwtClaims,
            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            val disclosures: Map<String, SelectiveDisclosureItem>,
            val isRevoked: Boolean,
        ) : VerifyCredentialResult()

        data class SuccessIso(val issuerSigned: IssuerSigned) : VerifyCredentialResult()
        data class Revoked(val input: String, val jws: VerifiableCredentialJws) : VerifyCredentialResult()
        data class InvalidStructure(val input: String) : VerifyCredentialResult()
    }

}

/**
 * Verifies that [input] is a valid identifier for this key
 */
fun CryptoPublicKey.matchesIdentifier(input: String): Boolean {
    if (jwkId == input)
        return true
    if (didEncoded == input)
        return true
    if (toJsonWebKey().keyId == input)
        return true
    if (toJsonWebKey().jwkThumbprint == input)
        return true
    if (toJsonWebKey().didEncoded == input)
        return true
    return false
}

class VerificationError(message: String?) : Throwable(message)
