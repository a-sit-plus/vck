package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
import at.asitplus.wallet.lib.agent.validation.CredentialTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatusValidationResult
import at.asitplus.wallet.lib.iso.IssuerSignedItem
import at.asitplus.wallet.lib.iso.MobileSecurityObject

/**
 * Intermediate class used by [at.asitplus.wallet.lib.agent.Validator.verifyDocument] when parsing an ISO document,
 * and also in [at.asitplus.wallet.lib.agent.VerifierAgent.verifyPresentationIsoMdoc].
 */
data class IsoDocumentParsed(
    val mso: MobileSecurityObject,
    val validItems: List<IssuerSignedItem> = listOf(),
    val invalidItems: List<IssuerSignedItem> = listOf(),
    val freshnessSummary: CredentialFreshnessSummary.Mdoc,
) {
    @Deprecated("Replaced with more expressive TokenStatusValidationResult, supporting token status values as defined by the library client.", ReplaceWith("freshnessSummary.tokenStatusValidationResult"))
    val tokenStatus: KmmResult<TokenStatus>?
        get() = when(val it = freshnessSummary.tokenStatusValidationResult) {
            is TokenStatusValidationResult.Invalid -> KmmResult.success(it.tokenStatus)
            is TokenStatusValidationResult.Rejected -> KmmResult.failure(it.throwable)
            is TokenStatusValidationResult.Valid -> it.tokenStatus?.let { KmmResult.success(it) }
        }

    @Deprecated("", ReplaceWith("freshnessSummary.timelinessValidationSummary"))
    val timelinessValidationSummary: CredentialTimelinessValidationSummary.Mdoc
        get() = freshnessSummary.timelinessValidationSummary
}