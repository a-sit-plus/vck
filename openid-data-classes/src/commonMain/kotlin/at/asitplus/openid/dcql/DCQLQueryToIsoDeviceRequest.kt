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
 * retain if any claims query for it has one.
 *
 * `claim_sets` request one of their options, in the order of the verifier's preference (OpenID4VP 1.0, 6.4.1), which
 * an `ItemsRequest` can not express. If one option is contained in every other one, the verifier accepts it, and
 * requesting exactly its claims asks for nothing the verifier does not accept, only for less than it prefers, so it is
 * requested. E.g. for `[[given_name, portrait], [given_name]]`, as built for claims requested if available, only
 * `given_name` is requested; a single option is requested as it is.
 *
 * This fails for every query that requests something else,
 * instead of silently requesting more or other than the query does:
 *  - a credential query that is not an [DCQLIsoMdocCredentialQuery], or has no [DCQLIsoMdocCredentialQuery.claims]:
 *    DCQL's absent `claims` requests the claims that are mandatory to present (OpenID4VP 1.0, 6.4.1), which an
 *    `ItemsRequest` can not express
 *  - `claim_sets` none of whose options is contained in every other one, i.e. alternatives such as
 *    `[[age_over_18], [birth_date]]`: requesting their common claims would ask for less than the verifier accepts
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
 * The claims queries of `claims`, or of the option of `claim_sets` that every other option contains, see
 * [toIso180137AnnexCDeviceRequest]. Fails if there is no such option, or it has no claim.
 */
private fun DCQLIsoMdocCredentialQuery.requestedClaims(): List<DCQLIsoMdocClaimsQuery> {
    val claims = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }
    val sets = claimSets
        ?: return claims.toList()
    val options = sets.map { it.toSet() }
    val option = options.firstOrNull { candidate -> options.all { it.containsAll(candidate) } }
        ?: throw IllegalArgumentException(
            "An ISO DeviceRequest can not express the claim combinations of $id, none is contained in all others"
        )
    val requested = claims.filter { it.id in option }
    require(requested.isNotEmpty()) {
        "An ISO DeviceRequest requests at least one data element, but the claim combination of $id has none"
    }
    return requested
}
