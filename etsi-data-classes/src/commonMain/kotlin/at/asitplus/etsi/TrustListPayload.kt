package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustListPayload(
    @SerialName("LoTE")
    val loTe: ListOfTrustedEntities
)