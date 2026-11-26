package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DeviceRequestMatchingResult
import at.asitplus.iso.DocRequestId
import at.asitplus.iso.DocRequestMatch
import at.asitplus.iso.DocRequestSubmissionOption
import at.asitplus.iso.Document
import at.asitplus.iso.IsoMdocCredential
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.checkAcceptedDocuments
import at.asitplus.iso.checkDisclosure
import at.asitplus.iso.checkUseCaseRequirements
import at.asitplus.iso.docRequestIds
import at.asitplus.iso.findDocRequestMatches
import at.asitplus.iso.itemsRequest
import at.asitplus.iso.match
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.cbor.authorityKeyIdentifiers
import at.asitplus.wallet.lib.data.MdocClaimReference
import at.asitplus.wallet.lib.procedures.dcql.DCQLQueryAdapter
import at.asitplus.wallet.lib.validation.CheckOutcome
import kotlin.jvm.JvmInline

/**
 * Adapts the credentials and submissions of a holder and the documents of a response to the rules of the ISO/IEC
 * 18013-5 [deviceRequest], see [DeviceRequest.findDocRequestMatches], [DeviceRequest.checkUseCaseRequirements] and
 * [DeviceRequest.checkAcceptedDocuments], as [DCQLQueryAdapter] adapts them to a DCQL query.
 */
@JvmInline
value class DeviceRequestAdapter(val deviceRequest: DeviceRequest) {

    /**
     * Matches every document request against each of [credentials], see [DeviceRequest.findDocRequestMatches]. A
     * credential that is not an ISO mdoc matches no document request, with the failure as its result, as
     * [DCQLQueryAdapter.select] treats a credential it can not read.
     */
    fun select(credentials: List<StoreEntry>): DeviceRequestMatchingResult {
        val isoCredentials = credentials.map { catchingUnwrapped { it.toIsoMdocCredential() } }
        return DeviceRequestMatchingResult(deviceRequest.docRequestIds.associateWith { id ->
            val itemsRequest = deviceRequest.itemsRequest(id)
            isoCredentials.map { credential ->
                credential.fold(
                    onSuccess = { itemsRequest.match(it) },
                    onFailure = { KmmResult.failure<DocRequestMatch>(it) },
                )
            }
        })
    }

    /**
     * Checks the holder's [submission] against [deviceRequest], also one a wallet builds itself, and creates the
     * parameters to present it, in the order of the document requests. The checks:
     *  - the submitted document requests satisfy the use cases, see [DeviceRequest.checkUseCaseRequirements]
     *  - a document request is submitted with one credential, unless its `uniqueDocSetRequired` is `false`, which
     *    indicates that "the mdoc reader [...] can receive multiple instances of responses to this exact DocRequest"
     *    (ISO/IEC DIS 18013-5:2026, 10.2.4), and never without a credential
     *  - each credential is an ISO mdoc of the requested docType, issued by an authority of the requested
     *    `issuerIdentifiers`, whose disclosed data elements answer the document request exactly, see
     *    [ItemsRequest.checkDisclosure]. So a wallet may disclose a later alternative than [ItemsRequest.match] selects.
     *
     * The parameters carry the ZK metadata of the `zkRequest` of the document request, if it has one.
     */
    fun createPresentationParameters(
        submission: Map<DocRequestId, List<DocRequestSubmissionOption<StoreEntry>>>,
    ): KmmResult<List<IsoPresentationParameters>> = catching {
        deviceRequest.checkUseCaseRequirements(submission.keys).getOrThrow()
        submission.entries.sortedBy { it.key.index }.flatMap { (id, options) ->
            val itemsRequest = deviceRequest.itemsRequest(id)
            require(options.isNotEmpty()) { "The document request $id is submitted without a credential" }
            require(options.size == 1 || itemsRequest.requestInfo?.uniqueDocSetRequired == false) {
                "The document request $id may only be submitted once"
            }
            options.map { it.toPresentationParameters(id, itemsRequest) }
        }
    }

    /** See [createPresentationParameters]. */
    private fun DocRequestSubmissionOption<StoreEntry>.toPresentationParameters(
        id: DocRequestId,
        itemsRequest: ItemsRequest,
    ): IsoPresentationParameters {
        val credential = credential as? StoreEntry.Iso
            ?: throw PresentationException("The document request $id requires an ISO mdoc credential")
        itemsRequest.checkDisclosure(credential.toIsoMdocCredential(), disclosedElements.toSet()).getOrThrow()
        return IsoPresentationParameters.create(
            credential = credential,
            claims = disclosedElements.map { MdocClaimReference(it.namespace, it.dataElementIdentifier) },
            zkMetadata = itemsRequest.requestInfo?.zkRequest?.let { ZkMetadata.IsoMdocZk(it) },
        ).getOrThrow()
    }

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

/**
 * This stored credential as the rules of a [DeviceRequest] see it, of the docType of its
 * [StoreEntry.Iso.schemeIdentifier], see [Document.toIsoMdocCredential]. Fails unless it is an ISO mdoc.
 */
internal fun StoreEntry.toIsoMdocCredential(): IsoMdocCredential {
    require(this is StoreEntry.Iso) { "Credential is not an ISO mdoc, but a ${this::class.simpleName}" }
    return IsoMdocCredential.of(
        docType = schemeIdentifier,
        issuerSigned = issuerSigned,
        authorityKeyIdentifiers = issuerSigned.issuerAuth.authorityKeyIdentifiers(),
    )
}
