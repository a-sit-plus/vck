package at.asitplus.wallet.lib.agent

import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.jwkId
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject


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
     * Verifies a presentation of some credentials from a holder,
     * that shall include the [challenge] (sent by this verifier).
     */
    fun verifyPresentation(it: String, challenge: String): VerifyPresentationResult

    sealed class VerifyPresentationResult {
        data class Success(val vp: VerifiablePresentationParsed) : VerifyPresentationResult()
        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            val reconstructedJsonObject: JsonObject,
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
            val reconstructedJsonObject: JsonObject,
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
    with(toJsonWebKey()) {
        if (keyId == input)
            return true
        if (jwkThumbprint == input)
            return true
        if (didEncoded == input)
            return true
    }
    return false
}

class VerificationError(message: String?) : Throwable(message)
