package at.asitplus.wallet.lib.data

import at.asitplus.catchingUnwrapped
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Instant

@Deprecated("Use InstantLongSerializer instead", replaceWith = ReplaceWith("InstantLongSerializer", imports = arrayOf("at.asitplus.signum.indispensable.io.InstantLongSerializer")), level = DeprecationLevel.WARNING)
class NullableInstantLongSerializer : KSerializer<Instant?> {
    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NullableInstantLongSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Instant? =
        catchingUnwrapped { Instant.fromEpochSeconds(decoder.decodeLong()) }.getOrNull()

    override fun serialize(encoder: Encoder, value: Instant?) {
        value?.let { encoder.encodeLong(it.epochSeconds) }
    }
}