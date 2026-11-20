package at.asitplus.openid.dcql

import at.asitplus.catchingUnwrapped
import at.asitplus.iso.DeviceRequest
import at.asitplus.iso.DocRequest
import at.asitplus.iso.ElementReference
import at.asitplus.iso.ItemsRequest
import at.asitplus.iso.ofCombinations
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import io.github.z4kn4fein.semver.Version

/**
 * Renders this DCQL query as an ISO 18013-5 [DeviceRequest],
 * to be used for ISO/IEC 18013-7 Annex C flows over the W3C Digital Credentials API.
 *
 * A `DeviceRequest` requests every one of its `DocRequests`, each with the listed data elements and their
 * `IntentToRetain` (ISO/IEC DIS 18013-5:2026, 10.2.3), and nothing more. A data element is requested once, as the
 * data elements are the keys of a map (`DataElements = {+ DataElementIdentifier => IntentToRetain}`, ibid.), with the
 * intent to retain if any claims query for it has one.
 *
 * `claim_sets` request one of their options, in the order of the verifier's preference (OpenID4VP 1.0, 6.4.1).
 * They are requested as alternative data elements (ISO/IEC DIS 18013-5:2026, 10.2.4), see
 * [ItemsRequest.Companion.ofCombinations]: e.g. `[[age_over_18], [birth_date]]` requests `age_over_18` with the
 * alternative `birth_date`.
 * If one option is contained in every other one, only that option is requested, as the verifier accepts it:
 * e.g. for `[[given_name, portrait], [given_name]]`, as built for claims requested if available, only `given_name`,
 * as ISO can not mark a data element as optional.
 *
 * This fails for every query that requests something else,
instead of silently requesting more or other than the query does:
 *  - a credential query that is not an [DCQLIsoMdocCredentialQuery], or has no [DCQLIsoMdocCredentialQuery.claims]:
 *    DCQL's absent `claims` requests the claims that are mandatory to present (OpenID4VP 1.0, 6.4.1),
 *    which an `ItemsRequest` can not express
 *  - `claim_sets` whose option contained in every other one has no claim,
 *    as an `ItemsRequest` requests at least one data element
 *  - `claim_sets` whose alternative data elements would be retained differently than the data elements they are
 *    alternatives to, see [ItemsRequest.Companion.ofCombinations]
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
    require(!multiple) {
        "An ISO DeviceRequest can not request multiple credentials for $id"
    }
    require(trustedAuthorities == null) {
        "An ISO DeviceRequest can not express the trusted authorities of $id"
    }
    val claims = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }
    val options = claimSets?.map { option ->
        claims.filter { it.id in option }.map { it.toElementReference() }.toSet()
    } ?: listOf(claims.map { it.toElementReference() }.toSet())
    val intentToRetain = claims.filter { it.intentToRetain == true }.map { it.toElementReference() }.toSet()
    val itemsRequest = catchingUnwrapped {
        ItemsRequest.ofCombinations(
            docType = meta.doctypeValue,
            common = setOf(),
            options = options,
            intentToRetain = intentToRetain,
        )
    }.getOrElse { throw IllegalArgumentException("An ISO DeviceRequest can not request the claims of $id", it) }
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

private fun DCQLIsoMdocClaimsQuery.toElementReference() = ElementReference(namespace, claimName)
