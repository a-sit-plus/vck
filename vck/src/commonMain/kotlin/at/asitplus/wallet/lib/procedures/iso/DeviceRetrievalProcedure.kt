package at.asitplus.wallet.lib.procedures.iso

import at.asitplus.KmmResult
import at.asitplus.catching
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.IssuerSigned
import at.asitplus.iso.ItemsRequest
import at.asitplus.jsonpath.core.NormalizedJsonPath
import at.asitplus.wallet.lib.IsoSdJwtKeyBinding
import at.asitplus.wallet.lib.agent.DeviceRequestCredentialDisclosure
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalClaimMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalCredentialMatch
import at.asitplus.wallet.lib.agent.IsoDeviceRetrievalQueryMatchingResult
import at.asitplus.wallet.lib.agent.IsoPresentationParameters
import at.asitplus.wallet.lib.agent.IsoSdJwtPresentationParameters
import at.asitplus.wallet.lib.agent.PresentationException
import at.asitplus.wallet.lib.agent.ZkMetadata
import at.asitplus.wallet.lib.agent.SubjectCredentialStore.StoreEntry
import at.asitplus.wallet.lib.data.CredentialToJsonConverter
import io.github.aakira.napier.Napier

/** The documents selected for an ISO Device Retrieval request: mdocs, and SD-JWT VCs (WG10 N2933 v2). */
internal data class DeviceRetrievalSelection(
    val mdocs: List<IsoPresentationParameters>,
    val sdJwts: List<IsoSdJwtPresentationParameters>,
)

/** Matching and submission validation for ISO Device Retrieval requests. */
internal object DeviceRetrievalProcedure {

    /** Bounds the combinations of alternative data elements tried for one SD-JWT document request. */
    private const val MAX_ALTERNATIVE_COMBINATIONS = 1024

    fun match(
        deviceRequest: DeviceRequest,
        credentials: List<StoreEntry>,
    ) = IsoDeviceRetrievalQueryMatchingResult(
        documentMatches = deviceRequest.docRequests.map { docRequest ->
            val itemsRequest = docRequest.itemsRequest.value
            if (itemsRequest.requestInfo?.isSdJwt == true) itemsRequest.matchSdJwt(credentials)
            else itemsRequest.match(credentials)
        },
    )

    fun validateSubmission(
        deviceRequest: DeviceRequest,
        submissions: Collection<DeviceRequestCredentialDisclosure<StoreEntry>>,
    ): KmmResult<DeviceRetrievalSelection> = catching {
        require(submissions.size == deviceRequest.docRequests.size) {
            "A submission is required for every document request"
        }
        val submissionsByRequest = submissions.associateBy { it.docRequestIndex }
        require(submissionsByRequest.size == submissions.size) { "A document request may only be submitted once" }

        val mdocs = mutableListOf<IsoPresentationParameters>()
        val sdJwts = mutableListOf<IsoSdJwtPresentationParameters>()
        deviceRequest.docRequests.forEachIndexed { index, docRequest ->
            val submission = submissionsByRequest[index]
                ?: throw PresentationException("Missing submission for document request at index $index")
            val itemsRequest = docRequest.itemsRequest.value
            if (itemsRequest.requestInfo?.isSdJwt == true) {
                sdJwts += itemsRequest.validateSdJwtSubmission(deviceRequest, index, submission)
            } else {
                mdocs += itemsRequest.validateMdocSubmission(index, submission)
            }
        }
        DeviceRetrievalSelection(mdocs, sdJwts)
    }

    private fun ItemsRequest.validateMdocSubmission(
        index: Int,
        submission: DeviceRequestCredentialDisclosure<StoreEntry>,
    ): IsoPresentationParameters {
        val credential = submission.credential as? StoreEntry.Iso
            ?: throw PresentationException("Document request at index $index requires an ISO mdoc credential")
        require(credential.schemeIdentifier == docType) {
            "Credential docType does not match document request at index $index"
        }
        val meta = requestInfo?.zkRequest?.let {
            ZkMetadata.IsoMdocZk(it)
        }
        val requiredPaths = evaluateItemsRequestAgainstCredential(
            itemsRequest = this,
            issuerSigned = credential.issuerSigned,
        ).getOrThrow().map { it.path }
        submission.requireDisclosing(requiredPaths, index)
        return IsoPresentationParameters.create(credential, submission.disclosedAttributes, meta).getOrThrow()
    }

    private fun ItemsRequest.validateSdJwtSubmission(
        deviceRequest: DeviceRequest,
        index: Int,
        submission: DeviceRequestCredentialDisclosure<StoreEntry>,
    ): IsoSdJwtPresentationParameters {
        val credential = submission.credential as? StoreEntry.SdJwt
            ?: throw PresentationException("Document request at index $index requires an SD-JWT VC")
        val requiredPaths = evaluateSdJwtItemsRequest(credential).getOrThrow().map { it.path }
        submission.requireDisclosing(requiredPaths, index)
        return IsoSdJwtPresentationParameters(
            docRequestIndex = index,
            credential = credential,
            claims = submission.disclosedAttributes,
            audience = IsoSdJwtKeyBinding.audience(deviceRequest, index),
        )
    }

    private fun DeviceRequestCredentialDisclosure<StoreEntry>.requireDisclosing(
        requiredPaths: List<NormalizedJsonPath>,
        index: Int,
    ) = require(disclosedAttributes.map { it.toString() }.toSet() == requiredPaths.map { it.toString() }.toSet()) {
        "Disclosed attributes do not exactly match document request at index $index"
    }

    private fun ItemsRequest.match(
        credentials: List<StoreEntry>,
    ): List<IsoDeviceRetrievalCredentialMatch> = credentials.also {
        Napier.d("Matching request for $docType against ${it.size} credential(s)")
    }.mapIndexedNotNull { index, credential ->
        (credential as? StoreEntry.Iso)
            ?.takeIf { it.schemeIdentifier == docType }
            ?.let {
                evaluateItemsRequestAgainstCredential(
                    itemsRequest = this,
                    issuerSigned = it.issuerSigned,
                ).onFailure { error ->
                    Napier.w("Credential at index $index does not match request for $docType", error)
                }.getOrNull()?.let { requestedClaims ->
                    IsoDeviceRetrievalCredentialMatch(
                        credentialIndex = index,
                        requestedClaims = requestedClaims,
                    )
                }
            }
    }

    private fun ItemsRequest.matchSdJwt(
        credentials: List<StoreEntry>,
    ): List<IsoDeviceRetrievalCredentialMatch> = credentials.mapIndexedNotNull { index, credential ->
        (credential as? StoreEntry.SdJwt)
            ?.takeIf { it.sdJwt.verifiableCredentialType == docType }
            ?.let {
                evaluateSdJwtItemsRequest(it).onFailure { error ->
                    Napier.w("Credential at index $index does not match SD-JWT request for $docType", error)
                }.getOrNull()?.let { requestedClaims ->
                    IsoDeviceRetrievalCredentialMatch(
                        credentialIndex = index,
                        requestedClaims = requestedClaims,
                    )
                }
            }
    }

    /**
     * Returns all requested claims only if the credential contains every requested namespace and data element.
     * `intentToRetain` controls verifier retention and does not make an element optional.
     */
    private fun evaluateItemsRequestAgainstCredential(
        itemsRequest: ItemsRequest,
        issuerSigned: IssuerSigned,
    ): KmmResult<List<IsoDeviceRetrievalClaimMatch>> = catching {
        itemsRequest.namespaces.flatMap { (namespace, requestedItems) ->
            requestedItems.entries.map { request ->
                val item = issuerSigned.namespaces?.get(namespace)?.entries
                    ?.firstOrNull { it.value.elementIdentifier == request.dataElementIdentifier }
                    ?.value
                    ?: throw PresentationException(
                        "Credential does not contain requested data element $['$namespace']['${request.dataElementIdentifier}']"
                    )
                IsoDeviceRetrievalClaimMatch(
                    namespace = namespace,
                    claimName = item.elementIdentifier,
                    claimValue = item.elementValue,
                )
            }
        }
    }

    /**
     * Returns the claims of [credential] an SD-JWT document request selects, if the credential satisfies it (WG10 N2933
     * v2, "DeviceRequest changes", proposed section 6.4.1, "Request processing logic"):
     *  - its `vct` is the requested `docType`, matched exactly, and it is bound to a key, as key binding is required;
     *  - claims are requested in the namespace `_` only, each data element identifier mapped to a claim path by
     *    `dataElementIdentifierMapping`, which selects claims as a claims path pointer does (SD-JWT VC, 4.6.1);
     *  - every requested data element is present, or all elements of one of its alternative sets, in the order of
     *    preference of `alternativeDataElements`: the first satisfiable combination is selected;
     *  - without requested data elements, only the claims that are always disclosed are presented.
     */
    // TODO N2933 v2 requests the mandatory claims only without claims, while its CDDL requires non-empty `nameSpaces`
    private fun ItemsRequest.evaluateSdJwtItemsRequest(
        credential: StoreEntry.SdJwt,
    ): KmmResult<List<IsoDeviceRetrievalClaimMatch>> = catching {
        require(credential.sdJwt.verifiableCredentialType == docType) { "The vct does not match $docType" }
        requireNotNull(credential.sdJwt.confirmationClaim) { "The SD-JWT VC is not bound to a key" }
        require(namespaces.keys.all { it == DocRequestInfo.SD_JWT_NAMESPACE }) {
            "Claims of an SD-JWT VC are only requested in the namespace ${DocRequestInfo.SD_JWT_NAMESPACE}"
        }
        val mapping = requestInfo?.dataElementIdentifierMapping.orEmpty()
        val requested = namespaces[DocRequestInfo.SD_JWT_NAMESPACE]?.entries.orEmpty().map { it.dataElementIdentifier }
        val json = CredentialToJsonConverter.toJsonElement(credential)

        fun select(identifier: String): List<IsoDeviceRetrievalClaimMatch>? =
            mapping[identifier]?.query(json)?.takeIf { it.isNotEmpty() }?.map {
                IsoDeviceRetrievalClaimMatch(
                    namespace = DocRequestInfo.SD_JWT_NAMESPACE,
                    claimName = identifier,
                    claimValue = it.value,
                    path = it.normalizedJsonPath,
                )
            }

        alternativeCombinations(requested).firstNotNullOfOrNull { combination ->
            combination.map { select(it) ?: return@firstNotNullOfOrNull null }.flatten()
        }?.distinctBy { it.path.toString() }
            ?: throw PresentationException("The SD-JWT VC does not contain the claims requested for $docType")
    }

    /**
     * The combinations of data element identifiers that satisfy [requested], in the order of preference: each element
     * itself first, then each of its alternative sets of `alternativeDataElements` in request order (ISO/IEC 18013-5
     * second edition, 10.2.4).
     */
    private fun ItemsRequest.alternativeCombinations(requested: List<String>): Sequence<List<String>> {
        val alternatives = requestInfo?.alternativeDataElements.orEmpty().associate { set ->
            require((listOf(set.requestedElement) + set.alternativeElementSets.flatten()).all {
                it.namespace == DocRequestInfo.SD_JWT_NAMESPACE
            }) { "Alternatives of an SD-JWT VC are only requested in the namespace ${DocRequestInfo.SD_JWT_NAMESPACE}" }
            set.requestedElement.dataElementIdentifier to set.alternativeElementSets.map { elements ->
                elements.map { it.dataElementIdentifier }
            }
        }
        val options = requested.map { listOf(listOf(it)) + alternatives[it].orEmpty() }
        var count = 1
        options.forEach {
            count *= it.size
            require(count <= MAX_ALTERNATIVE_COMBINATIONS) { "Too many combinations of alternative data elements" }
        }
        return options.fold(sequenceOf(emptyList())) { combinations, option ->
            combinations.flatMap { combination -> option.asSequence().map { combination + it } }
        }
    }
}
