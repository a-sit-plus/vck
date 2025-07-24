package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject

sealed class AuthnResponseResult {
    /**
     * Error in parsing the URL or content itself, before verifying the contents of the OpenId response
     */
    data class Error(val reason: String, val state: String?, val cause: Throwable? = null) : AuthnResponseResult()

    /**
     * Error when validating the `vpToken` or `idToken`
     */
    data class ValidationError(val field: String, val state: String?, val cause: Throwable? = null) :
        AuthnResponseResult()

    /**
     * Wallet provided an `id_token`, no `vp_token` (as requested by us!)
     */
    data class IdToken(val idToken: at.asitplus.openid.IdToken, val state: String?) : AuthnResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiablePresentationValidationResults(val validationResults: List<AuthnResponseResult>) :
        AuthnResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiableDCQLPresentationValidationResults(val validationResults: Map<DCQLCredentialQueryIdentifier, AuthnResponseResult>) :
        AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (VC in JWT)
     */
    data class Success(
        val vp: VerifiablePresentationParsed,
        val state: String?,
    ) : AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (SD-JWT VC)
     */
    data class SuccessSdJwt(
        val sdJwtSigned: SdJwtSigned,
        val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
        val reconstructed: JsonObject,
        val disclosures: Collection<SelectiveDisclosureItem>,
        val state: String?,
        val freshnessSummary: CredentialFreshnessSummary.SdJwt,
    ) : AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (ISO mDoc credential)
     */
    data class SuccessIso(
        val documents: Collection<IsoDocumentParsed>,
        val state: String?,
    ) : AuthnResponseResult()
}