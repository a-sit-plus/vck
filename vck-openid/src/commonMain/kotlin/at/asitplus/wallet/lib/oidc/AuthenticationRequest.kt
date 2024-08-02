@file:UseSerializers(JwsSignedSerializer::class, UrlSerializer::class)

package at.asitplus.wallet.lib.oidc


import at.asitplus.catching
import at.asitplus.signum.indispensable.josef.JwsSigned
import io.ktor.http.*
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.UseSerializers
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToString
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
        val jwsSigned: at.asitplus.signum.indispensable.josef.JwsSigned,
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

internal object JwsSignedSerializer : KSerializer<JwsSigned> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("JwsSignedSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): JwsSigned = JwsSigned.parse(decoder.decodeString()).getOrThrow()

    override fun serialize(encoder: Encoder, value: JwsSigned) {
        encoder.encodeString(value.serialize())
    }

}

internal object UrlSerializer : KSerializer<Url> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("UrlSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Url = Url(decoder.decodeString())

    override fun serialize(encoder: Encoder, value: Url) {
        encoder.encodeString(value.toString())
    }

}
