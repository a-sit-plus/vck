package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.Document
import at.asitplus.iso.IsoMdocCredential
import at.asitplus.iso.checkAcceptedDocuments
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CheckOutcome
import kotlin.jvm.JvmInline

/**
 * Adapts the documents of a response to the rules of the ISO/IEC 18013-5 [deviceRequest] they answer, see
 * [DeviceRequest.checkAcceptedDocuments], as [DCQLQueryAdapter] adapts the presentations of a DCQL query.
 */
@JvmInline
value class DeviceRequestAdapter(val deviceRequest: DeviceRequest) {

    /**
     * Whether the accepted [documents] of a response satisfy [deviceRequest], see
     * [DeviceRequest.checkAcceptedDocuments]: some document requests satisfy its use cases, each answered by its own
     * document (ISO/IEC DIS 18013-5:2026, 10.2.4, 10.2.8 step 1).
     *
     * Only accepted documents count: a rejected one counts as if it had not been returned, so the response is only
     * rejected if the request can not be satisfied without it. Only issuer-signed data elements count, as only these
     * are attested by the issuer, and error codes instead of data elements (ISO/IEC 18013-5:2021, 8.3.2.1.2.2) do not
     * satisfy a request.
     */
    fun checkAcceptedDocuments(documents: List<Document>): CheckOutcome =
        deviceRequest.checkAcceptedDocuments(documents.map { it.toIsoMdocCredential() }).fold(
            onSuccess = { CheckOutcome.Passed },
            onFailure = { CheckOutcome.Failed(it) },
        )
}

/**
 * This document as the rules of a [DeviceRequest] see it, with the authority key identifiers of the `x5chain` of its
 * `IssuerAuth`, see [authorityKeyIdentifiers].
 */
internal fun Document.toIsoMdocCredential() = IsoMdocCredential.of(
    docType = docType,
    issuerSigned = issuerSigned,
    authorityKeyIdentifiers = issuerSigned.issuerAuth.authorityKeyIdentifiers(),
)
