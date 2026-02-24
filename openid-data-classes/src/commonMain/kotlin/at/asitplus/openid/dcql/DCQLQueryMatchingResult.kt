package at.asitplus.openid.dcql

import at.asitplus.KmmResult


@Deprecated("Use DCQLQueryMatchingResult instead")
typealias DCQLQueryResult<Any> = DCQLQueryMatchingResult

data class DCQLQueryMatchingResult(
    /**
     * each entry in the result list refers to the credential at the same index from those provided for matching
     */
    val credentialMatchingResults: Map<DCQLCredentialQueryIdentifier, List<KmmResult<DCQLCredentialQueryMatchingResult>>>,
) {
    val credentialQueryMatches = credentialMatchingResults.mapValues {
        it.value.mapIndexed { index, result ->
            result.getOrNull()?.let {
                index.toUInt() to it
            }
        }.filterNotNull()
    }
}



