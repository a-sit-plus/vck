package at.asitplus.openid.dcql

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.DocRequestInfo
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.github.z4kn4fein.semver.Version

/**
 * Renders this DCQL query as an ISO 18013-5 [DeviceRequest],
 * to be used for ISO/IEC 18013-7 Annex C flows over the W3C Digital Credentials API.
 *
 * Every credential query needs explicitly enumerated claims: DCQL's `claims == null` (requesting all claims)
 * cannot be expressed in an ISO device request. A [DCQLIsoMdocCredentialQuery] becomes an mdoc document request, a
 * [DCQLSdJwtCredentialQuery] an SD-JWT document request of WG10 N2933 v2, see [toSdJwtDocRequest].
 */
fun DCQLQuery.toIso180137AnnexCDeviceRequest(): DeviceRequest = DeviceRequest(
    parsedVersion = Version(1, 0),
    docRequests = credentials.map { it.toDocRequest() }.toTypedArray(),
)

private fun DCQLCredentialQuery.toDocRequest(): DocRequest = when (this) {
    is DCQLIsoMdocCredentialQuery -> toMdocDocRequest()
    is DCQLSdJwtCredentialQuery -> toSdJwtDocRequest()
    else -> throw IllegalArgumentException(
        "Only mso_mdoc and dc+sd-jwt credential queries are supported for ISO 18013-7 Annex C, got $format"
    )
}

private fun DCQLIsoMdocCredentialQuery.toMdocDocRequest(): DocRequest {
    val namespaces = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }.groupBy(
        keySelector = { it.namespace },
        valueTransform = { SingleItemsRequest(it.claimName, it.intentToRetain ?: false) },
    ).mapValues { (_, items) -> ItemsRequestList(items) }
    return DocRequest(ByteStringWrapper(ItemsRequest(meta.doctypeValue, namespaces)))
}

/**
 * An SD-JWT document request (WG10 N2933 v2, "DeviceRequest changes"): the single `vct` as `docType`, every claims
 * query as a data element of the namespace [DocRequestInfo.SD_JWT_NAMESPACE], identified by the id of the claims
 * query, or else by its path (see [dataElementIdentifier]), and mapped to its claims path pointer by
 * [DocRequestInfo.dataElementIdentifierMapping].
 *
 * `claim_sets` are rejected, as alternatives of an ISO request replace single data elements, which do not express
 * every combination of claims, and so are `values`, which ISO requests do not support.
 */
private fun DCQLSdJwtCredentialQuery.toSdJwtDocRequest(): DocRequest {
    val claimsQueries = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }
    require(claimSets == null) { "claim_sets can not be expressed in an ISO device request" }
    require(claimsQueries.none { it.values != null }) { "Claim values can not be expressed in an ISO device request" }
    val vct = requireNotNull(meta.vctValues.singleOrNull()) {
        "An ISO device request requests an SD-JWT VC of exactly one vct"
    }
    val mapping = claimsQueries.map { query ->
        (query.id?.string ?: query.path.dataElementIdentifier()) to query.path
    }
    require(mapping.map { it.first }.distinct().size == mapping.size) {
        "The data element identifiers of an ISO device request must be unique"
    }
    return DocRequest(
        ByteStringWrapper(
            ItemsRequest(
                docType = vct,
                namespaces = mapOf(
                    DocRequestInfo.SD_JWT_NAMESPACE to ItemsRequestList(
                        mapping.map { (identifier, _) -> SingleItemsRequest(identifier, false) }
                    )
                ),
                requestInfo = DocRequestInfo(
                    docFormat = DocRequestInfo.DOC_FORMAT_SD_JWT,
                    dataElementIdentifierMapping = mapping.toMap(),
                ),
            )
        )
    )
}

/**
 * A readable data element identifier for this claims path pointer, e.g. shown by a wallet: its components joined by
 * `.`, a name as is, an index as a decimal, and `null` as `*`, e.g. `address.formatted` or `nationalities.*`.
 */
private fun DCQLClaimsPathPointer.dataElementIdentifier(): String = segments.joinToString(".") {
    when (it) {
        is DCQLClaimsPathPointerSegment.NameSegment -> it.name
        is DCQLClaimsPathPointerSegment.IndexSegment -> it.index.toString()
        DCQLClaimsPathPointerSegment.NullSegment -> "*"
    }
}
