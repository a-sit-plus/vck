package at.asitplus.openid.dcql

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.UseCase
import at.asitplus.iso.forUseCases
import at.asitplus.iso.ofCombinations
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper

/**
 * Renders this DCQL query as an ISO/IEC 18013-5 [DeviceRequest] for ISO/IEC 18013-7 Annex C over the W3C Digital
 * Credentials API, requesting what the query requests (ISO/IEC DIS 18013-5:2026, 10.2):
 *
 *  - each credential query a credential set requests is a `DocRequest`, the others are left out (OpenID4VP 1.0, 6.4.2)
 *  - `claim_sets` are alternative data elements, see [ItemsRequest.Companion.ofCombinations]
 *  - `credential_sets` are use cases, see [DeviceRequest.Companion.forUseCases]
 *  - `multiple` is `uniqueDocSetRequired = !multiple`, always set, as ISO recommends (10.2.4)
 *  - `trusted_authorities` of type `aki` are the `issuerIdentifiers` (OpenID4VP 1.0, 6.1.1; 10.2.4)
 *  - a data element queried twice is requested once, retained if any of its claims queries retains it
 *
 * Fails instead of requesting more or other than the query: for credential queries other than `mso_mdoc` or without
 * `claims`, which request the claims mandatory to present (OpenID4VP 1.0, 6.4.1), for `credential_sets` that are all
 * optional, as ISO requires "at least one UseCase" (10.2.5), for `trusted_authorities` of another type than `aki`, for
 * expected claim `values` of a requested data element (OpenID4VP 1.0, 6.3), and for what
 * [ItemsRequest.Companion.ofCombinations] and [DeviceRequest.Companion.forUseCases] reject, e.g. a credential set
 * with an option contained in another one.
 */
fun DCQLQuery.toIso180137AnnexCDeviceRequest(): DeviceRequest {
    require(requestedCredentialSetQueries.any { it.required }) {
        "An ISO DeviceRequest requires at least one use case, but every credential set is optional"
    }
    val docRequests = credentials.filter { query ->
        requestedCredentialSetQueries.any { set -> set.options.any { query.id in it } }
    }
    val docPositions = docRequests.withIndex().associate { it.value.id to it.index.toUInt() }
    val useCases = requestedCredentialSetQueries.map { set ->
        UseCase(
            mandatory = set.required,
            documentSets = set.options.map { option ->
                option.map { id -> requireNotNull(docPositions[id]) { "No credential query has the ID $id" } }
            },
        )
    }
    return DeviceRequest.forUseCases(
        docRequests = docRequests.map { it.toDocRequest() },
        useCases = useCases
    )
}

private fun DCQLCredentialQuery.toDocRequest(): DocRequest {
    require(this is DCQLIsoMdocCredentialQuery) {
        "Only mso_mdoc credential queries are supported for ISO 18013-7 Annex C, got $format"
    }
    requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }
    val issuerIdentifiers = trustedAuthorities?.flatMap { entry ->
        require(entry is DCQLTrustedAuthorityQueryEntryAuthorityKeyIdentifier) {
            "An ISO DeviceRequest can express trusted authorities of type aki only, but $id has ${entry.type}"
        }
        entry.authorityKeyIdentifiers
    }?.distinct()?.map { it.byteArray }
    val claimSetOptions = claimSets?.map { claimSetIdentifier ->
        claims.filter { it.id in claimSetIdentifier }.toElementReferences()
    } ?: listOf(claims.toElementReferences())
    val intentToRetain = claims.filter { it.intentToRetain == true }.toElementReferences()
    val itemsRequest = catchingUnwrapped {
        ItemsRequest.ofCombinations(
            docType = meta.doctypeValue,
            common = setOf(),
            options = claimSetOptions,
            intentToRetain = intentToRetain,
            requestInfo = DocRequestInfo(
                uniqueDocSetRequired = !multiple,
                issuerIdentifiers = issuerIdentifiers
            ),
        )
    }.getOrElse {
        throw IllegalArgumentException("An ISO DeviceRequest can not request the claims of $id", it)
    }
    val requestedElements = itemsRequest.requestedElements()
    require(claims.none { it.values != null && it.toElementReference() in requestedElements }) {
        "An ISO DeviceRequest can not express expected values in $id"
    }
    return DocRequest(ByteStringWrapper(itemsRequest))
}

/** The data elements this request requests, and their alternatives. */
private fun ItemsRequest.requestedElements(): Set<ElementReference> {
    val requested = namespaces.flatMap { (namespace, list) ->
        list.entries.map { ElementReference(namespace, it.dataElementIdentifier) }
    }
    val alternatives = requestInfo?.alternativeDataElements.orEmpty().flatMap { it.alternativeElementSets.flatten() }
    return (requested + alternatives).toSet()
}

private fun List<DCQLIsoMdocClaimsQuery>.toElementReferences() = map { it.toElementReference() }.toSet()

private fun DCQLIsoMdocClaimsQuery.toElementReference() = ElementReference(namespace, claimName)
