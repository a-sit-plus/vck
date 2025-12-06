package at.asitplus.wallet.lib.iso

import at.asitplus.openid.dcql.DCQLCredentialQueryIdentifier
import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed

sealed class ResponseResult {
    /**
     * Error in parsing the content itself, before verifying the contents of the response
     */
    data class Error(
        val reason: String,
        val cause: Throwable? = null,
    ) : ResponseResult()

    /**
     * Error when validating
     */
    data class ValidationError(
        val cause: Throwable? = null,
    ) : ResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet
     */
    data class Success(
        val vp: VerifiablePresentationParsed,
    ) : ResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (ISO mDoc credential)
     */
    data class SuccessIso(
        val documents: Collection<IsoDocumentParsed>,
    ) : ResponseResult()
}
