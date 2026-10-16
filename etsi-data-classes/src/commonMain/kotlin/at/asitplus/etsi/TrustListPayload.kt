package at.asitplus.etsi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

@Serializable
data class TrustListPayload(
    /** List of trusted entities carried by the JSON payload (TS 119 602, Annex A.1). */
    @SerialName("LoTE")
    val loTe: ListOfTrustedEntities
)