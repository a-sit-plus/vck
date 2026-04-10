package at.asitplus.wallet.lib.iso

import at.asitplus.wallet.lib.data.IsoDocumentParsed

/**
 * Validation results of ISO 18013-7 presentation
 */
data class Iso180137AnnexCVerifiedPresentationResult(
    val documents: Collection<IsoDocumentParsed>,
)