package at.asitplus.dcapi

import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
@ConsistentCopyVisibility
@Serializable
data class Oid4vpDCAPIResponse private constructor(

    @SerialName("response")
    val response: String,
) {
    companion object {

        fun createOid4vpResponse(response: String): Oid4vpDCAPIResponse  =
            Oid4vpDCAPIResponse(response)
            //DCAPIResponse(response)
    }
}