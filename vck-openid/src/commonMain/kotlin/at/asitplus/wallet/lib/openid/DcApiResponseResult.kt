package at.asitplus.wallet.lib.openid

import at.asitplus.wallet.lib.data.IsoDocumentParsed

/** Result of validating a DCAPI response, see [DcApiVerifier.validateAuthnResponse] */
sealed interface DcApiResponseResult

/**
 * Result of validating an ISO/IEC 18013-7 Annex C response, see [DcApiVerifier.validateAuthnResponse]
 * and [DcApiCreationOptions.Iso180137AnnexC]: the documents, or the error status of the wallet's device response.
 */
sealed interface Iso180137AnnexCResult : DcApiResponseResult

/**
 * Result of validating an ISO 18013-7 Annex C response, see [DcApiVerifier.validateAuthnResponse]
 * and [DcApiCreationOptions.Iso180137AnnexC]
 */
data class Iso180137AnnexCWrapper(
    val documents: Collection<IsoDocumentParsed>
) : Iso180137AnnexCResult

/**
 * The wallet answered an ISO/IEC 18013-7 Annex C request with a device response carrying an error [status] instead
 * of documents (ISO/IEC 18013-5, 10.3.6): 10 for a general error, 11 for a CBOR decoding error, 12 for a CBOR
 * validation error. Annex C defines no other error, so this is the only one that reaches the verifier: declining or
 * failing otherwise rejects the request in the browser. Like a presentation, it ends the request.
 *
 * The status is bound to the request by the encryption of the response, but not authenticated by the mdoc, as it
 * comes without a device signature.
 */
data class Iso180137AnnexCError(
    val status: UInt,
) : Iso180137AnnexCResult