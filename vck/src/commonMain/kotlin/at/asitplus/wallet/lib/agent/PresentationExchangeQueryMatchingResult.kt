package at.asitplus.wallet.lib.agent

import at.asitplus.KmmResult

@Deprecated("Support for Presentation Exchange has been removed from OpenID4VP; use DCQL or DeviceRequest")
data class PresentationExchangeQueryMatchingResult(
    val inputDescriptorMatchingResults: Map<String, List<KmmResult<InputDescriptorMatching>>>
) {
    val inputDescriptorMatches = inputDescriptorMatchingResults.mapValues {
        it.value.mapIndexedNotNull { index, matchingResult ->
            matchingResult.getOrNull()?.let {
                index.toUInt() to it
            }
        }.toMap()
    }
}
