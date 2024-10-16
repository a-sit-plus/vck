package at.asitplus.openid


import at.asitplus.catching
import at.asitplus.rqes.serializers.UrlSerializer
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString

@Serializable
sealed class AuthenticationRequestParametersFrom : RequestParametersFrom {

    fun serialize(): String = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String) =
            catching { jsonSerializer.decodeFromString<AuthenticationRequestParametersFrom>(input) }
    }

    abstract override val parameters: AuthenticationRequestParameters

    @Serializable
    @SerialName("JwsSigned")
    data class JwsSigned(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned,
        override val parameters: AuthenticationRequestParameters,
    ) : AuthenticationRequestParametersFrom()

    @Serializable
    @SerialName("Uri")
    data class Uri(
        @Serializable(UrlSerializer::class)
        val url: Url,
        override val parameters: AuthenticationRequestParameters,
    ) : AuthenticationRequestParametersFrom()

    @Serializable
    @SerialName("Json")
    data class Json(
        val jsonString: String,
        override val parameters: AuthenticationRequestParameters,
    ) : AuthenticationRequestParametersFrom()
}


