package at.asitplus.rqes

import at.asitplus.catching
import at.asitplus.openid.JwsSignedSerializer
import at.asitplus.openid.RequestParametersFrom
import at.asitplus.openid.UrlSerializer
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString


@Serializable
sealed class SignatureRequestParametersFrom : RequestParametersFrom {
    fun serialize(): String = rdcJsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String) =
            catching { rdcJsonSerializer.decodeFromString<SignatureRequestParameters>(input) }
    }

    abstract override val parameters: SignatureRequestParameters

    @Serializable
    @SerialName("JwsSigned")
    data class JwsSigned(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<ByteArray>,
        override val parameters: SignatureRequestParameters,
    ) : SignatureRequestParametersFrom()

    @Serializable
    @SerialName("Uri")
    data class Uri(
        @Serializable(UrlSerializer::class)
        val url: Url,
        override val parameters: SignatureRequestParameters,
    ) : SignatureRequestParametersFrom()

    @Serializable
    @SerialName("Json")
    data class Json(
        val jsonString: String,
        override val parameters: SignatureRequestParameters,
    ) : SignatureRequestParametersFrom()

}