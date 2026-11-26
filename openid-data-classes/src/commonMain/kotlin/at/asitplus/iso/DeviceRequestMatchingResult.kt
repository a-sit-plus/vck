package at.asitplus.iso

import at.asitplus.KmmResult

/**
 * How credentials match the document requests of a [DeviceRequest], see [DeviceRequest.findDocRequestMatches], the
 * counterpart of [at.asitplus.openid.dcql.DCQLQueryMatchingResult] for DCQL.
 */
data class DeviceRequestMatchingResult(
    /**
     * For each document request, one result per credential, in the order of the credentials provided for matching;
     * a failure tells why the credential does not match.
     */
    val docRequestMatchingResults: Map<DocRequestId, List<KmmResult<DocRequestMatch>>>,
) {
    /** The successful matches of each document request, by the index of the credential, in the order of these. */
    val docRequestMatches: Map<DocRequestId, List<Pair<UInt, DocRequestMatch>>> =
        docRequestMatchingResults.mapValues { (_, results) ->
            results.mapIndexedNotNull { index, result -> result.getOrNull()?.let { index.toUInt() to it } }
        }
}
