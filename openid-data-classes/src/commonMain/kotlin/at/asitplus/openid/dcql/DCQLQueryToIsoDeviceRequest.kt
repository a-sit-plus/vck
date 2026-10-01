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
 * All credential queries must be [DCQLIsoMdocCredentialQuery] with explicitly enumerated
 * [DCQLIsoMdocCredentialQuery.claims]: DCQL's `claims == null` (requesting all claims)
 * cannot be expressed in an ISO device request.
 */
fun DCQLQuery.toIso180137AnnexCDeviceRequest(): DeviceRequest = DeviceRequest(
    parsedVersion = Version(1, 0),
    docRequests = credentials.map { it.toDocRequest() }.toTypedArray(),
)

private fun DCQLCredentialQuery.toDocRequest(): DocRequest {
    require(this is DCQLIsoMdocCredentialQuery) {
        "Only mso_mdoc credential queries are supported for ISO 18013-7 Annex C, got $format"
    }
    val namespaces = requireNotNull(claims) {
        "ISO device requests require explicitly enumerated claims"
    }.groupBy(
        keySelector = { it.namespace },
        valueTransform = { SingleItemsRequest(it.claimName, it.intentToRetain ?: false) },
    ).mapValues { (_, items) -> ItemsRequestList(items) }
    return DocRequest(ByteStringWrapper(ItemsRequest(meta.doctypeValue, namespaces)))
}
