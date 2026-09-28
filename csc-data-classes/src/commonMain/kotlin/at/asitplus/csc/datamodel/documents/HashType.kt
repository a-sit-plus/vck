package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** Identifies the meaning of [DocumentInfo.hash]. */
@Serializable
enum class HashType {
    @SerialName("sdr")
    SDR,

    @SerialName("dtbsr")
    DTBSR,

    @SerialName("sodr")
    SODR,
}