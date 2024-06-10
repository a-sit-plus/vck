package at.asitplus.wallet.lib.oidc

import at.asitplus.crypto.datatypes.jws.JwsSigned
import at.asitplus.wallet.lib.data.UrlSerializer
import io.ktor.http.Url
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder


@Serializable
sealed class AuthenticationRequestSource {
    @Serializable
    data class JwsSigned(
        @Serializable(with = JwsSignedSerializer::class) val jwsSigned: at.asitplus.crypto.datatypes.jws.JwsSigned,
    ) : AuthenticationRequestSource()

    @Serializable
    data class Uri(
        @Serializable(with = UrlSerializer::class) val url: Url,
    ) : AuthenticationRequestSource()

    @Serializable
    data class Json(
        val jsonString: String,
    ) : AuthenticationRequestSource()
}




/**
 * kotlinx-serializer for JwsSigned, which simply uses the transforms defined within the class.
 */
// TODO: maybe create a serializer for JwsSigned directly in kmp-crypto?
object JwsSignedSerializer : KSerializer<JwsSigned> {
    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("at.asitplus.wallet.lib.oidc.JwsSignedSerializer", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: JwsSigned) {
        encoder.encodeString(value.serialize())
    }

    override fun deserialize(decoder: Decoder): JwsSigned {
        return JwsSigned.parse(decoder.decodeString()).getOrThrow()
    }
}
