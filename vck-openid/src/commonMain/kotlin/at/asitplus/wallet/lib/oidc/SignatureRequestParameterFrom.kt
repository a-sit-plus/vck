package at.asitplus.wallet.lib.oidc

import at.asitplus.catching
import at.asitplus.dif.rqes.serializers.UrlSerializer
import at.asitplus.openid.JwsSignedSerializer
import at.asitplus.openid.SignatureRequestParameters
import io.ktor.http.*
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString


@Serializable
sealed class SignatureRequestParametersFrom : RequestParametersFrom {
    fun serialize(): String = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String) =
            catching { jsonSerializer.decodeFromString<SignatureRequestParameters>(input) }
    }

    abstract override val parameters: SignatureRequestParameters

    @Serializable
    @SerialName("JwsSigned")
    data class JwsSigned(
        @Serializable(JwsSignedSerializer::class)
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned,
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