package at.asitplus.etsi

import at.asitplus.signum.indispensable.pki.X509Certificate
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.jsonArray

/** Rejects null certificate wire entries while retaining unavailable results from individual certificate parsers. */
class EtsiX509CertificateListSerializer : KSerializer<List<X509Certificate?>> {
    /** Array serializer retaining unavailable results from individual certificate parsers. */
    private val delegate = ListSerializer(EtsiX509CertificateSerializer())
    /** Descriptor of the certificate array in the JSON binding. */
    override val descriptor = delegate.descriptor

    override fun deserialize(decoder: Decoder): List<X509Certificate?> {
        if (decoder is JsonDecoder) {
            val entries = decoder.decodeJsonElement().jsonArray
            require(entries.isNotEmpty() && entries.none { it == JsonNull }) {
                "Expected a non-empty array of certificate objects, without null entries."
            }
            return decoder.json.decodeFromJsonElement(delegate, entries)
        }
        return decoder.decodeSerializableValue(delegate)
    }

    override fun serialize(encoder: Encoder, value: List<X509Certificate?>) {
        require(value.isNotEmpty() && value.none { it == null }) {
            "Unavailable certificates cannot be emitted as valid certificate objects."
        }
        encoder.encodeSerializableValue(delegate, value)
    }
}
