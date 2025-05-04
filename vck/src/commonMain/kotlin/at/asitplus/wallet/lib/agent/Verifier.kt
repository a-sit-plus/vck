package at.asitplus.wallet.lib.agent

import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.jwkId
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.data.*
import at.asitplus.wallet.lib.iso.DeviceResponse
import at.asitplus.wallet.lib.iso.Document
import at.asitplus.wallet.lib.iso.IssuerSigned
import at.asitplus.wallet.lib.iso.MobileSecurityObject
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject


/**
 * Summarizes operations for a Verifier in the sense of the [W3C VC Data Model](https://w3c.github.io/vc-data-model/).
 *
 * It can verify credentials and presentations.
 */
interface Verifier {
    /**
     * Verifies a presentation of some credentials in [ConstantIndex.CredentialRepresentation.SD_JWT] from a holder,
     * that shall include the [challenge] (sent by this verifier).
     */
    suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: Pair<PresentationRequestParameters.Flow, List<TransactionDataBase64Url>>? = null,
    ): VerifyPresentationResult

    /**
     * Verifies a presentation of some credentials in [ConstantIndex.CredentialRepresentation.PLAIN_JWT] from a holder,
     * that shall include the [challenge] (sent by this verifier).
     */
    suspend fun verifyPresentationVcJwt(
        input: JwsSigned<VerifiablePresentationJws>,
        challenge: String,
    ): VerifyPresentationResult

    /**
     * Verifies a presentation of some credentials in [ConstantIndex.CredentialRepresentation.ISO_MDOC] from a holder,
     * that shall include the [challenge] (sent by this verifier).
     */
    suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        challenge: String,
        verifyDocument: (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult

    sealed class VerifyPresentationResult {
        data class Success(val vp: VerifiablePresentationParsed) : VerifyPresentationResult()
        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            val reconstructedJsonObject: JsonObject,
            val disclosures: Collection<SelectiveDisclosureItem>,
            val isRevoked: Boolean,
        ) : VerifyPresentationResult()

        data class SuccessIso(val documents: List<IsoDocumentParsed>) : VerifyPresentationResult()
        data class InvalidStructure(val input: String) : VerifyPresentationResult()
        data class ValidationError(val cause: Throwable) : VerifyPresentationResult() {
            constructor(message: String) : this(Throwable(message))
        }
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
        data class ValidationError(val cause: Throwable) : VerifyCredentialResult() {
            constructor(message: String) : this(Throwable(message))
        }
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
