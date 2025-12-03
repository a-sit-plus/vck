package at.asitplus.wallet.lib.iso

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed

sealed class ResponseResult {

    /**
     * Error in parsing the URL or content itself, before verifying the contents of the OpenId response
     */
    data class Error(
        val reason: String,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
        val cause: Throwable? = null,
    ) : ResponseResult()

    /**
     * Error when validating the `vpToken` or `idToken`
     */
    data class ValidationError(
        val field: String,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
        val cause: Throwable? = null,
    ) : ResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiablePresentationValidationResults(
        val validationResults: List<ResponseResult>,
    ) : ResponseResult()

    /**
     * Validation results of all returned verifiable presentations
     */
    data class VerifiableDCQLPresentationValidationResults(
        val validationResults: Map<DCQLCredentialQueryIdentifier, ResponseResult>,
    ) : ResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (VC in JWT)
     */
    data class Success(
        val vp: VerifiablePresentationParsed,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
    ) : ResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (ISO mDoc credential)
     */
    data class SuccessIso(
        val documents: Collection<IsoDocumentParsed>,
        @Deprecated("Will be removed in release after 5.10.0")
        val state: String? = null,
    ) : ResponseResult()
}
