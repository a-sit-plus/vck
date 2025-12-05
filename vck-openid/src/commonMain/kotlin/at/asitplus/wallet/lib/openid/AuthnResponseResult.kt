package at.asitplus.wallet.lib.openid

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.SelectiveDisclosureItem
import at.asitplus.wallet.lib.data.VerifiableCredentialSdJwt
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed
import at.asitplus.wallet.lib.iso.ResponseResult
import at.asitplus.wallet.lib.jws.SdJwtSigned
import kotlinx.serialization.json.JsonObject

sealed class AuthnResponseResult {
    /**
     * Error in parsing the URL or content itself, before verifying the contents of the OpenId response
     */
    data class Error(
        val reason: String,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
        val cause: Throwable? = null,
    ) : AuthnResponseResult()

    /**
     * Error when validating the `vpToken` or `idToken`
     */
    data class ValidationError(
        val field: String,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
        val cause: Throwable? = null,
    ) : AuthnResponseResult()

    /**
     * Wallet provided an `id_token`, no `vp_token` (as requested by us!)
     */
    data class IdToken(
        val idToken: at.asitplus.openid.IdToken,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
    ) : AuthnResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiablePresentationValidationResults(
        val validationResults: List<AuthnResponseResult>,
    ) : AuthnResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiableDCQLPresentationValidationResults(
        val validationResults: Map<DCQLCredentialQueryIdentifier, AuthnResponseResult>,
    ) : AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (VC in JWT)
     */
    data class Success(
        val vp: VerifiablePresentationParsed,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
    ) : AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (SD-JWT VC)
     */
    data class SuccessSdJwt(
        val sdJwtSigned: SdJwtSigned,
        val verifiableCredentialSdJwt: VerifiableCredentialSdJwt,
        val reconstructed: JsonObject,
        val disclosures: Collection<SelectiveDisclosureItem>,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
        val freshnessSummary: CredentialFreshnessSummary.SdJwt,
    ) : AuthnResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (ISO mDoc credential)
     */
    data class SuccessIso(
        val documents: Collection<IsoDocumentParsed>,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
    ) : AuthnResponseResult()
}