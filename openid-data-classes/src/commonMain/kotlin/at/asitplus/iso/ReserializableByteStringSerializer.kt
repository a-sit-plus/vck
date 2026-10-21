package at.asitplus.iso

import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapper
import at.asitplus.signum.indispensable.cosef.io.ByteStringWrapperSerializer
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ByteArraySerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/**
 * Like [ByteStringWrapperSerializer], but writes [ByteStringWrapper.serialized] as it is if present, so a decoded
 * value is serialized again to the same bytes, and only encodes [ByteStringWrapper.value] without it.
 */
class ReserializableByteStringSerializer<T>(dataSerializer: KSerializer<T>) :
    KSerializer<ByteStringWrapper<T>> {

    private val default = ByteStringWrapperSerializer(dataSerializer)

    override val descriptor: SerialDescriptor = default.descriptor

    override fun serialize(encoder: Encoder, value: ByteStringWrapper<T>) {
        if (value.serialized.isNotEmpty()) {
            encoder.encodeSerializableValue(ByteArraySerializer(), value.serialized)
        } else {
            default.serialize(encoder, value)
        }
    }

    override fun deserialize(decoder: Decoder): ByteStringWrapper<T> = default.deserialize(decoder)
}
