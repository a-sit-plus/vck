package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.cbor.ByteString
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Identifier = bstr
 *
 * !! This only works correctly if the cbor serializer uses `alwaysUseByteString = true`
 * !! because a custom serializer does not honor the @ByteString annotation. Currently it is only cosmetic.
 *
 * Things that do not work at time of writing(21.11.2025):
 * I.   We cannot use ByteArray directly because of kotlins way of handling equality and kotlinx handling of @ByteString
 * II.  We cannot use value class bc its jvm specific and even then equality cannot be correctly implemented bc I.
 * III. We cannot use the default serializer of [Identifier] because you would encode the class instead of just [value]
 * IV.  We cannot force the custom serializer to use Type 2 Major type (aka @ByteString) when encoding [value]
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
        override val descriptor = buildClassSerialDescriptor("at.asitplus.wallet.lib.data.iso18013.Identifier")

        override fun serialize(encoder: Encoder, value: Identifier) {
            encoder.encodeSerializableValue(delegate, value.value)
        }

        override fun deserialize(decoder: Decoder): Identifier {
            return Identifier(decoder.decodeSerializableValue(delegate))
        }
    }
}
