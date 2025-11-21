package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * IdentifierList = {
 * "identifiers" : { * Identifier => IdentifierInfo },
 * ? "aggregation_uri" : Aggregation_uri
 * * tstr => RFU (Not implemented)
 * }
 *
 * Since the [identifiers] map keys are bytearrays we need to define a wrapper to handle equality in a meaningful way
 * also it is impossible to annotate a type with @ByteString as this only works on actual class members so the
 * value would be incorrect anyways
 */
@Serializable
data class IdentifierList(
    @SerialName("identifiers")
    val identifiers: Map<Identifier, IdentifierInfo>,
    @SerialName("aggregation_uri")
    val aggregationUri: String? = null,
)