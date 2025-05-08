package at.asitplus.wallet.lib.data

import at.asitplus.KmmResult
import at.asitplus.wallet.lib.agent.validation.mdoc.MdocTimelinessValidationSummary
import at.asitplus.wallet.lib.data.rfc.tokenStatusList.primitives.TokenStatus
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
    val tokenStatus: KmmResult<TokenStatus>?,
    val timelinessValidationSummary: MdocTimelinessValidationSummary,
)