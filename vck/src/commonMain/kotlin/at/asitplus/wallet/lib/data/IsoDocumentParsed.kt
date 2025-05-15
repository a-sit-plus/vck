package at.asitplus.wallet.lib.data

import at.asitplus.wallet.lib.agent.validation.CredentialFreshnessSummary
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
    @Deprecated("Replaced with more expressive freshness information", ReplaceWith("""freshnessSummary.let { when(it.tokenStatusValidationResult) {
            is TokenStatusValidationResult.Rejected -> null
            is TokenStatusValidationResult.Invalid -> true
            is TokenStatusValidationResult.Valid -> false
        }}"""))
    val isRevoked: Boolean?
        get() = when(freshnessSummary.tokenStatusValidationResult) {
            is TokenStatusValidationResult.Rejected -> null
            is TokenStatusValidationResult.Invalid -> true
            is TokenStatusValidationResult.Valid -> false
        }
}