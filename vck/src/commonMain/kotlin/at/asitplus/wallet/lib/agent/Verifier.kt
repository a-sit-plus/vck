package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult
import at.asitplus.iso.DeviceResponse
import at.asitplus.iso.Document
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.MobileSecurityObject
import at.asitplus.openid.TransactionDataBase64Url
import at.asitplus.signum.indispensable.CryptoPublicKey
import at.asitplus.signum.indispensable.josef.JwsCompactTyped
import at.asitplus.signum.indispensable.josef.toJsonWebKey
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VcJwsVerificationResultWrapper
import at.asitplus.wallet.lib.data.VerifiableCredentialPayload
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
     * Verifies a presentation of some credentials in
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.SD_JWT] from a holder,
     * that shall include the [challenge] (sent by this verifier).
     * @param audience Exact audience expected in the key binding JWT. When `null`, [VerifierAgent] uses its configured
     * verifier identifier. Protocol callers must supply their transport-specific audience; OpenID4VP normally uses
     * its Client Identifier, while OpenID4VP over the DC API uses `origin:<origin>`.
     */
    suspend fun verifyPresentationSdJwt(
        input: SdJwtSigned,
        challenge: String,
        transactionData: List<TransactionDataBase64Url>? = null,
        requireCryptographicHolderBinding: Boolean = true,
        audience: String? = null,
    ): KmmResult<VerifyPresentationResult.SuccessSdJwt>

    /**
     * Verifies a presentation of some credentials in
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT] from a holder,
     * that shall include the [challenge] (sent by this verifier).
     */
    suspend fun verifyPresentationVcJwt(
        input: JwsCompactTyped<VerifiablePresentationJws>,
        challenge: String,
    ): KmmResult<VerifyPresentationResult.Success>

    /**
     * Verifies a presentation of one credential in
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.PLAIN_JWT] from a holder,
     * without a holder key binding, which would be chacked in [verifyPresentationVcJwt].
     */
    suspend fun verifyUnsignedVcJws(
        input: String
    ): KmmResult<VerifyPresentationResult.SuccessUnsigned>

    /**
     * Verifies a presentation of some credentials in
     * [at.asitplus.wallet.lib.data.ConstantIndex.CredentialRepresentation.ISO_MDOC] from a holder,
     * with a challenge validated by the callback in [verifyDocument] (i.e. device authentication for OpenID4VP).
     */
    suspend fun verifyPresentationIsoMdoc(
        input: DeviceResponse,
        verifyDocument: suspend (MobileSecurityObject, Document) -> Boolean,
    ): KmmResult<VerifyPresentationResult.SuccessIso>

    sealed class VerifyPresentationResult {
        data class SuccessUnsigned(
            val vc: VcJwsVerificationResultWrapper,
        ) : VerifyPresentationResult()

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
    }

    sealed class VerifyCredentialResult {
        data class SuccessJwt(
            val jws: VerifiableCredentialPayload,
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
