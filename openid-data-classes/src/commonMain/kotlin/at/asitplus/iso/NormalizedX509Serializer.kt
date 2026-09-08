package at.asitplus.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Custom serializer for a certificate chain (`List<ByteArray>`).
 *
 * **Serialization (Writing):** Complies with RFC 9360, Section 2 by writing a single certificate
 * directly as a raw CBOR Byte String (`bstr`), and multiple certificates as a CBOR Array of
 * Byte Strings (`[ 2* bstr ]`).
 *
 * **Deserialization (Reading):** Strictly expects a CBOR Array format (`[ * bstr ]`) for any
 * certificate list (which is why upstream pre-normalization (e.g. via [ZkDocumentDataWrapperSerializer])
 * is required to convert single raw `bstr` values into 1-item arrays).
 *
 * `null` values are supported through standard property nullability.
 */
object NormalizedX509Serializer : KSerializer<List<ByteArray>> {
    private val listSerializer = ListSerializer(ByteArraySerializer())

    override val descriptor: SerialDescriptor =
        SerialDescriptor("NormalizedListX509", listSerializer.descriptor)

    /**
     * Serializes a list of byte arrays representing X.509 certificates into the specified encoder
     * according to [RFC 9360, Section 2](https://www.rfc-editor.org/rfc/rfc9360.html#section-2).
     *
     * Depending on the size of the certificate chain (e.g., the `x5chain` parameter),
     * the CBOR encoding format differs:
     * - **Single Certificate:** Encoded directly as a single CBOR Byte String (`bstr`).
     * - **Multiple Certificates:** Encoded as a CBOR Array of Byte Strings (`[ 2* bstr ]`).
     *
     *
     * @param encoder The encoder to serialize data into.
     * @param value The list of byte arrays (certificates) to encode.
     */
    override fun serialize(encoder: Encoder, value: List<ByteArray>) = when {
        value.size == 1 -> encoder.encodeSerializableValue(ByteArraySerializer(), value.first())
        else -> encoder.encodeSerializableValue(listSerializer, value)
    }

    /**
     * Deserializes a list of X.509 certificates from the specified decoder.
     *
     * **Warning:** This deserializer assumes the input has already been normalized into a
     * CBOR Array of Byte Strings (e.g., via [ZkDocumentDataWrapperSerializer]). It does not
     * support raw single byte strings (`bstr`) to avoid unsafe decoding failures caused by
     * `kotlinx.serialization`'s streaming decoder limitations.
     *
     * @param decoder The decoder to read data from.
     * @return The list of byte arrays representing the certificates.
     */
    override fun deserialize(decoder: Decoder): List<ByteArray> =
        decoder.decodeSerializableValue(listSerializer)
}