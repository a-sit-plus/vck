package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.coseCompliantSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.decodeFromByteArray
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encodeToByteArray
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import net.orandja.obor.codec.Cbor
import net.orandja.obor.data.CborArray
import net.orandja.obor.data.CborBytes
import net.orandja.obor.data.CborMap
import net.orandja.obor.data.CborText

/**
 * Custom serializer wrapper for [ZkDocumentData] that bridges a limitation in
 * `kotlinx.serialization` regarding [RFC 9360, Section 2](https://www.rfc-editor.org/rfc/rfc9360.html#section-2) polymorphism.
 *
 * According to RFC 9360 (used in ISO/IEC 18013-5 for parameters like `msoX5chain`),
 * certificate chains can be encoded as either a single CBOR Byte String (`bstr`)
 * or an Array of Byte Strings (`[ 2* bstr ]`).
 *
 * **Normalization Behavior:**
 * This wrapper uses `obor` to inspect the raw CBOR payload. If the certificate chain
 * (`msoX5chain`) is present as a single byte string, it **normalizes** it by wrapping it into a
 * 1-item CBOR Array. This guarantees that `kotlinx.serialization` (via [NormalizedX509Serializer])
 * always encounters a uniform list structure, independent of whether 1 or multiple items
 * (or null) are present.
 *
 * @see [NormalizedX509Serializer] for `msoX5chain` (de-)serialization.
 */
object ZkDocumentDataWrapperSerializer : KSerializer<ByteStringWrapper<ZkDocumentData>> {

    override val descriptor: SerialDescriptor =
        SerialDescriptor("ByteStringWrapperZkDocumentData", ByteArraySerializer().descriptor)

    override fun deserialize(decoder: Decoder): ByteStringWrapper<ZkDocumentData> {
        val rawBytes = decoder.decodeSerializableValue(ByteArraySerializer())
        val normalizedBytes = normalizeCertificateChain(rawBytes)
        val parsedData = coseCompliantSerializer.decodeFromByteArray(ZkDocumentData.serializer(), normalizedBytes)
        return ByteStringWrapper(parsedData)
    }

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<ZkDocumentData>) =
        encoder.encodeSerializableValue(
            ByteStringWrapper.serializer(ZkDocumentData.serializer()),
            value
        )

    private fun normalizeCertificateChain(rawBytes: ByteArray): ByteArray {
        val targetKey = CborText(ZkDocumentData.PROP_CERT_CHAIN)
        val item = Cbor.decodeFromByteArray<CborMap>(rawBytes)
        val index = item.elements.indexOfFirst { it.key == targetKey }
        if (index == -1 || item.elements[index].value !is CborBytes) {
            return rawBytes
        }

        val targetEntry = item.elements[index]
        val wrappedArray = CborArray(mutableListOf(targetEntry.value), false)
        item.elements[index] = targetEntry.copy(value = wrappedArray)

        return Cbor.encodeToByteArray(CborMap(item.elements, false))
    }
}
