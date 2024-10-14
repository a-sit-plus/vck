package at.asitplus.wallet.lib.oidc


import at.asitplus.catching
import at.asitplus.dif.rqes.serializers.UrlSerializer
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JwsSigned
import io.ktor.http.*
import kotlinx.serialization.*
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable
sealed class AuthenticationRequestParametersFrom {

    fun serialize(): String = jsonSerializer.encodeToString(this)

    companion object {
        fun deserialize(input: String) =
            catching { jsonSerializer.decodeFromString<AuthenticationRequestParametersFrom>(input) }
    }

    abstract val parameters: AuthenticationRequestParameters

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

internal object JwsSignedSerializer : KSerializer<JwsSigned> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsSignedSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JwsSigned = JwsSigned.deserialize(decoder.decodeString()).getOrThrow()

    override fun serialize(encoder: Encoder, value: JwsSigned) {
        encoder.encodeString(value.serialize())
    }

}