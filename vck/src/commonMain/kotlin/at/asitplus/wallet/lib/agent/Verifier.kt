package at.asitplus.wallet.lib.agent

import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.data.ConstantIndex
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialJws
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationJws
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
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
        transactionData: List<TransactionDataBase64Url>? = null,
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
     * with a challenge validated by the callback in [verifyDocument] (i.e. device authentication for OpenID4VP).
     */
    suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
    ): VerifyPresentationResult

    sealed class VerifyPresentationResult {
        data class Success(
            val vp: VerifiablePresentationParsed,
        ) : VerifyPresentationResult()

        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            val reconstructedJsonObject: JsonObject,
            val disclosures: Collection<SelectiveDisclosureItem>,
            val freshnessSummary: CredentialFreshnessSummary.SdJwt,
        ) : VerifyPresentationResult()

        data class SuccessIso(
            val documents: List<IsoDocumentParsed>,
        ) : VerifyPresentationResult()

        data class ValidationError(
            val cause: Throwable,
        ) : VerifyPresentationResult() {
            constructor(message: String) : this(Throwable(message))
        }
    }

    sealed class VerifyCredentialResult {
        data class SuccessJwt(
            val jws: VerifiableCredentialJws,
        ) : VerifyCredentialResult()

        data class SuccessSdJwt(
            val sdJwtSigned: SdJwtSigned,
            val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
            val reconstructedJsonObject: JsonObject,
            /** Map of serialized disclosure item (as [String]) to parsed item (as [SelectiveDisclosureItem]) */
            val disclosures: Map<String, SelectiveDisclosureItem>,
        ) : VerifyCredentialResult()

        data class SuccessIso(
            val issuerSigned: IssuerSigned,
        ) : VerifyCredentialResult()

        data class ValidationError(
            val cause: Throwable,
        ) : VerifyCredentialResult() {
            constructor(message: String) : this(Throwable(message))
        }
    }

}

/**
 * Verifies that [input] is a valid identifier for this key (that is not forgeable like a simple ID)
 */
fun CryptoPublicKey.matchesIdentifier(input: String): Boolean {
    if (didEncoded == input)
        return true
    with(toJsonWebKey()) {
        if (jwkThumbprint == input)
            return true
        if (didEncoded == input)
            return true
    }
    return false
}

class VerificationError(cause: Throwable) : Throwable(cause)
