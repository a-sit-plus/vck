@file:UseSerializers(JwsSignedSerializer::class, UrlSerializer::class)

package at.asitplus.wallet.lib.oidc


import at.asitplus.catching
import at.asitplus.dif.rqes.UrlSerializer
import at.asitplus.openid.AuthenticationRequestParameters
import at.asitplus.signum.indispensable.josef.JwsSigned
import at.asitplus.wallet.lib.data.vckJsonSerializer
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
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned<AuthenticationRequestParameters>,
        override val parameters: AuthenticationRequestParameters,
    ) : AuthenticationRequestParametersFrom()

    @Serializable
    @SerialName("Uri")
    data class Uri(
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

internal object JwsSignedSerializer : KSerializer<JwsSigned<AuthenticationRequestParameters>> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsSignedSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JwsSigned<AuthenticationRequestParameters> =
        JwsSigned.deserialize<AuthenticationRequestParameters>(decoder.decodeString(), vckJsonSerializer).getOrThrow()

    override fun serialize(encoder: Encoder, value: JwsSigned<AuthenticationRequestParameters>) {
        encoder.encodeString(value.serialize())
    }

}