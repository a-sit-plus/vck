package at.asitplus.openid.dcql

import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ItemsRequestList
import at.asitplus.iso.SingleItemsRequest
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.github.z4kn4fein.semver.Version

/**
 * Renders this DCQL query as an ISO 18013-5 [DeviceRequest],
 * to be used for ISO/IEC 18013-7 Annex C flows over the W3C Digital Credentials API.
 *
 * A `DeviceRequest` requests every one of its `DocRequests`, each with the listed data elements and their
 * `IntentToRetain` (ISO/IEC 18013-5:2021, 8.3.2.1.2.1), and nothing more. A data element is requested once, as the
 * data elements are the keys of a map (`DataElements = {+ DataElement => IntentToRetain}`, ibid.), with the intent to
 * retain if any claims query for it has one. `claim_sets` with a single option request exactly the claims of that
 * option (OpenID4VP 1.0, 6.4.1), so those are requested.
 * This fails for every query that requests something else,
 * instead of silently requesting more or other than the query does:
 *  - a credential query that is not an [DCQLIsoMdocCredentialQuery], or has no [DCQLIsoMdocCredentialQuery.claims]:
 *    DCQL's absent `claims` requests the claims that are mandatory to present (OpenID4VP 1.0, 6.4.1), which an
 *    `ItemsRequest` can not express
 *  - several claim combinations in `claim_sets`, of which the wallet presents one (OpenID4VP 1.0, 6.4.1)
 *  - `credential_sets` other than required sets with a single option that together request every credential query,
 *    as other sets request alternative or optional credentials (OpenID4VP 1.0, 6.4.2)
 *  - expected claim `values` (OpenID4VP 1.0, 6.3), `multiple` credentials for one query, and `trusted_authorities`
 *    (OpenID4VP 1.0, 6.1)
 */
fun DCQLQuery.toIso180137AnnexCDeviceRequest(): DeviceRequest {
    requireEveryCredentialRequired()
    return DeviceRequest(
        parsedVersion = Version(1, 0),
        docRequests = credentials.map { it.toDocRequest() }.toTypedArray(),
    )
}

private fun DCQLQuery.requireEveryCredentialRequired() {
    val sets = credentialSets ?: return
    require(sets.all { it.required && it.options.size == 1 }) {
        "An ISO DeviceRequest requests every credential, but credential_sets request alternative or optional ones"
    }
    val notRequested = credentials.map { it.id }.toSet() - sets.flatMap { it.options.single() }.toSet()
    require(notRequested.isEmpty()) {
        "An ISO DeviceRequest requests every credential, but credential_sets do not request $notRequested"
    }
}

private fun DCQLCredentialQuery.toDocRequest(): DocRequest {
    require(this is DCQLIsoMdocCredentialQuery) {
        "Only mso_mdoc credential queries are supported for ISO 18013-7 Annex C, got $format"
    }
    val claims = requestedClaims()
    require(!multiple) {
        "An ISO DeviceRequest can not request multiple credentials for $id"
    }
    require(trustedAuthorities == null) {
        "An ISO DeviceRequest can not express the trusted authorities of $id"
    }
    require(claims.none { it.values != null }) {
        "An ISO DeviceRequest can not express expected values in $id"
    }
    val namespaces = claims.groupBy { it.namespace }.mapValues { (_, queries) ->
        ItemsRequestList(
            queries.groupBy { it.claimName }.map { (claimName, queriesOfElement) ->
                SingleItemsRequest(claimName, queriesOfElement.any { it.intentToRetain == true })
            }
        )
    }
    return DocRequest(ByteStringWrapper(ItemsRequest(docType = meta.doctypeValue, namespaces = namespaces)))
}

/**
 * The claims queries of `claims`, or of the single option of `claim_sets`, which requests exactly those
 * (OpenID4VP 1.0, 6.4.1). Fails for several options, of which the wallet presents one, and without any claim.
 */
private fun DCQLIsoMdocCredentialQuery.requestedClaims(): List<DCQLIsoMdocClaimsQuery> {
    val claims = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }
    val sets = claimSets
        ?: return claims.toList()
    require(sets.size == 1) {
        "An ISO DeviceRequest can not express the claim combinations of $id"
    }
    val option = sets.single().toSet()
    val requested = claims.filter { it.id in option }
    require(requested.isNotEmpty()) {
        "An ISO DeviceRequest requests at least one data element, but the claim combination of $id has none"
    }
    return requested
}
