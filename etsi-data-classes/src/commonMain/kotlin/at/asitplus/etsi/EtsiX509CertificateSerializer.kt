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

class EtsiX509CertificateSerializer : KSerializer<X509Certificate?> {
    /** Serializer for the JSON surrogate wrapping a Base64-encoded X.509 certificate. */
    private val delegate = EtsiX509CertificateSerializationSurrogate.serializer()
    /** Serialization descriptor for the JSON certificate surrogate. */
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

    /**
     * Because the underlying parser enforces strict ASN.1 validation,
     * parsing these "in-the-wild" certificates can throw exceptions. This catch block ensures
     * a single malformed certificate does not crash the deserialization of the entire trusted list.
     */
    override fun deserialize(decoder: Decoder): X509Certificate? = try {
        if (decoder is JsonDecoder) {
            val element = decoder.decodeJsonElement()
            decoder.json.decodeFromJsonElement(delegate, element).value
        } else {
            decoder.decodeSerializableValue(delegate).value
        }
    } catch (_: Exception) {
        null
    }

    @Serializable
    private data class EtsiX509CertificateSerializationSurrogate(
        /** X.509 certificate represented as a Base64 string in the JSON surrogate (TS 119 602, 6.6.3.1). */
        @SerialName(SerialNames.VALUE)
        @Serializable(with = X509CertificateBase64Serializer::class)
        val value: X509Certificate
    ) {
        object SerialNames {
            /** Wire member name `val`. */
            const val VALUE = "val"
        }
    }
}
