package at.asitplus.rqes

import at.asitplus.rqes.serializers.SignatureResponseSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.JsonObject

@Serializable(with = SignatureResponseSerializer::class)
sealed class SignatureResponse {

    @Serializable
    data class SignHashResponse(
        @SerialName("signatures")
        val signatures: List<String>,
        @SerialName("responseID")
        val responseId: String?,
    ) : SignatureResponse()

    @Serializable
    data class SignDocResponse(
        @SerialName("DocumentWithSignature")
        val documentWithSignature: List<String>?,
        @SerialName("SignatureObject")
        val signatureObject: List<String>?,
        @SerialName("responseID")
        val responseId: String?,
        @SerialName("validationInfo")
        val validationInfo: JsonObject?,
    ) : SignatureResponse()
}
