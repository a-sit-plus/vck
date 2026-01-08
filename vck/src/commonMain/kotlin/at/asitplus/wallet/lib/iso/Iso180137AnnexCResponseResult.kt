package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.IsoDocumentParsed
import at.asitplus.wallet.lib.data.VerifiablePresentationParsed

/**
 * Validation results of ISO 18013-7 presentation
 */
sealed class Iso180137AnnexCResponseResult {
    /**
     * Error in parsing the content itself, before verifying the contents of the response
     */
    data class Error(
        val reason: String,
        val cause: Throwable? = null,
    ) : Iso180137AnnexCResponseResult()

    /**
     * Error when validating
     */
    data class ValidationError(
        val cause: Throwable? = null,
    ) : Iso180137AnnexCResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet
     */
    data class Success(
        val vp: VerifiablePresentationParsed,
    ) : Iso180137AnnexCResponseResult()

    /**
     * Successfully decoded and validated the response from the Wallet (ISO mDoc credential)
     */
    data class SuccessIso(
        val documents: Collection<IsoDocumentParsed>,
    ) : Iso180137AnnexCResponseResult()
}
