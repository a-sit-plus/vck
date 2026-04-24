package at.asitplus.etsi

import at.asitplus.signum.indispensable.io.X509CertificateBase64Serializer
import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder

class EtsiX509CertificateSerializer : KSerializer<X509Certificate> {
    private val delegate = EtsiX509CertificateSerializationSurrogate.serializer()
    override val descriptor: SerialDescriptor
        get() = SerialDescriptor(
            serialName = EtsiX509CertificateSerializer::class.qualifiedName!!,
            original = delegate.descriptor,
        )

    override fun serialize(
        encoder: Encoder,
        value: X509Certificate
    ) {
        encoder.encodeSerializableValue(
            EtsiX509CertificateSerializationSurrogate.serializer(),
            EtsiX509CertificateSerializationSurrogate(
                value = value,
            )
        )
    }

    override fun deserialize(decoder: Decoder): X509Certificate {
        decoder as JsonDecoder
        val element = decoder.decodeJsonElement()
        println("element: $element")

        return decoder.json.decodeFromJsonElement(
            EtsiX509CertificateSerializationSurrogate.serializer(),
            element
        ).value
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
