package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.SerializationException
import kotlinx.serialization.cbor.CborDecoder
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Because the IdentifierInfo map keys may be either tstr or int we
 * need a class which keeps track of the specific key type
 */
@Serializable(with = IdentifierInfoKey.Serializer::class)
sealed class IdentifierInfoKey {
    abstract val key: Any
    data class KeyString(override val key: String) : IdentifierInfoKey()
    data class KeyInt(override val key: Int) : IdentifierInfoKey()

    object Serializer : KSerializer<IdentifierInfoKey> {
        override val descriptor: SerialDescriptor =
            PrimitiveSerialDescriptor("IdentifierInfoKey", PrimitiveKind.STRING)

        override fun serialize(encoder: Encoder, value: IdentifierInfoKey) {
            when (value) {
                is KeyString -> encoder.encodeString(value.key)
                is KeyInt -> encoder.encodeInt(value.key)
            }
        }

        override fun deserialize(decoder: Decoder): IdentifierInfoKey {
            // We don't have type info here, so we have to pick one.
            // For ISO 18013-5/7, RFU is currently unused and examples
            // typically use string keys so we default to string.
            return try {
                KeyString(decoder.decodeString())
            } catch (e: SerializationException) {
                KeyInt(decoder.decodeInt())
            }
        }
    }
}