package at.asitplus.etsi

import at.asitplus.signum.indispensable.io.X509CertificateBase64Serializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.io.encoding.Base64

class EtsiX509CertificateSerializer : KSerializer<X509Certificate?> {
    private val delegate = EtsiX509CertificateSerializationSurrogate.serializer()
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            serialName = EtsiX509CertificateSerializer::class.qualifiedName!!,
            original = delegate.descriptor,
        )

    override fun serialize(
        encoder: Encoder,
        value: X509Certificate?
    ) {
        if (value == null) return encoder.encodeNull()

        encoder.encodeSerializableValue(
            EtsiX509CertificateSerializationSurrogate.serializer(),
            EtsiX509CertificateSerializationSurrogate(
                value = value,
            )
        )
    }

    override fun deserialize(decoder: Decoder): X509Certificate? = try {
        when (decoder) {
            is JsonDecoder -> {
                val jsonObject = decoder
                    .decodeJsonElement()
                    .jsonObject

                val base64 = jsonObject[
                    EtsiX509CertificateSerializationSurrogate.SerialNames.VALUE
                ]?.jsonPrimitive?.content ?: return null

                val bytes = Base64.Default.decode(base64)

                X509Certificate.decodeFromByteArray(bytes)
            }
            else -> {
                decoder.decodeSerializableValue(
                    EtsiX509CertificateSerializationSurrogate.serializer(),
                ).value
            }
        }
    } catch (_: Exception) {
        null
    }

    @Serializable
    private data class EtsiX509CertificateSerializationSurrogate(
        @SerialName(SerialNames.VALUE)
        @Serializable(with = X509CertificateBase64Serializer::class)
        val value: X509Certificate
    ) {
        object SerialNames {
            const val VALUE = "val"
        }
    }
}
