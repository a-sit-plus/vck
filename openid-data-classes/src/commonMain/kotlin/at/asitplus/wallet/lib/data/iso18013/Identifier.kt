package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Identifier = bstr
 *
 * Needs to be a class containing member with ByteString annotation for correct cbor major type
 * and compatability as map key
 */
@Serializable(with = Identifier.Serializer::class)
data class Identifier(@ByteString val value: ByteArray) {

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other == null || this::class != other::class) return false

        other as Identifier

        return value.contentEquals(other.value)
    }

    override fun hashCode(): Int = value.contentHashCode()

    object Serializer : KSerializer<Identifier> {
        private val delegate = ByteArraySerializer()
        override val descriptor: SerialDescriptor = delegate.descriptor

        override fun serialize(encoder: Encoder, value: Identifier) {
            encoder.encodeSerializableValue(delegate, value.value)
        }

        override fun deserialize(decoder: Decoder): Identifier {
            return Identifier(decoder.decodeSerializableValue(delegate))
        }
    }
}
