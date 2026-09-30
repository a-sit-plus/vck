package at.asitplus.csc.datamodel.documents

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable


/** CSC Data Model 1.0.0 section 8.2: Identifies the meaning of [DocumentInfo.hash]. */
@Serializable
enum class HashType {
    @SerialName("sdr")
    SDR,

    @SerialName("dtbsr")
    DTBSR,

    @SerialName("sodr")
    SODR,
}
