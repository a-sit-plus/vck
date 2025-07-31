package at.asitplus.wallet.lib.data

import at.asitplus.catchingUnwrapped
import kotlin.time.Instant
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

class NullableInstantStringSerializer : KSerializer<Instant?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("NullableInstantStringSerializer", PrimitiveKind.STRING)

    override fun deserialize(decoder: Decoder): Instant? =
        catchingUnwrapped { Instant.parse(decoder.decodeString()) }.getOrNull()

    override fun serialize(encoder: Encoder, value: Instant?) {
        value?.let { encoder.encodeString(it.toString()) }
    }

}