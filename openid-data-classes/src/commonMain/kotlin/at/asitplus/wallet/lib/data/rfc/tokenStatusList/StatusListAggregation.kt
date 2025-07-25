package at.asitplus.wallet.lib.data.rfc.tokenStatusList

import at.asitplus.wallet.lib.data.rfc3986.UniformResourceIdentifier
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Status List Aggregation is an optional mechanism to retrieve a list of URIs to all Status List
 * Tokens, allowing a Relying Party to fetch all relevant Status Lists for a specific type of
 * Referenced Token or Issuer. This mechanism is intended to support fetching and caching
 * mechanisms and allow offline validation of the status of a reference token for a period of time.
 * If a Relying Party encounters an invalid Status List referenced in the response from the Status
 * List Aggregation endpoint, it SHOULD continue processing the other valid Status Lists referenced
 * in the response.There are two options for a Relying Party to retrieve the Status List
 * Aggregation. An Issuer MAY support any of these mechanisms:
 *
 * Issuer metadata: The Issuer of the Referenced Token publishes an URI which links to Status List
 * Aggregation, e.g. in publicly available metadata of an issuance protocol
 *
 * Status List Parameter: The Status Issuer includes an additional claim in the Status List Token
 * that contains the Status List Aggregation URI.
 */
@Serializable
data class StatusListAggregation(
    @SerialName("status_lists")
    val statusLists: List<UniformResourceIdentifier>,
)