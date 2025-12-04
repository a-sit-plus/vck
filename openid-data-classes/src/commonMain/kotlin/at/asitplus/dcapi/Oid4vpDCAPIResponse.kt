package at.asitplus.dcapi

import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import at.asitplus.signum.indispensable.io.Base64UrlStrict
import at.asitplus.signum.indispensable.io.TransformingSerializerTemplate
import io.matthewnelson.encoding.core.Decoder.Companion.decodeToByteArray
import io.matthewnelson.encoding.core.Encoder.Companion.encodeToString
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.encodeToByteArray

@ConsistentCopyVisibility
@Serializable
data class Oid4vpDCAPIResponse private constructor(

    @SerialName("response")
    val response: String,
) {
    companion object {

        fun createOid4vpResponse(response: String): DCAPIResponse  {
            TODO() }
            //DCAPIResponse(response)
    }
}