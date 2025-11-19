package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * IdentifierList = {
 * "identifiers" : { * Identifier => IdentifierInfo },
 * ? "aggregation_uri" : Aggregation_uri
 * * tstr => RFU (Not implemented)
 * }
 */
@Serializable
data class IdentifierList(
    @SerialName("identifiers")
    val identifiers: Map<Identifier, IdentifierInfo>,
    @SerialName("aggregation_uri")
    val aggregationUri: String? = null,
)
