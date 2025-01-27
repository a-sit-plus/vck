package at.asitplus.openid

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds


object DurationSecondsIntSerializer : KSerializer<Duration> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("DurationSecondsIntSerializer", PrimitiveKind.LONG)

    override fun deserialize(decoder: Decoder): Duration = decoder.decodeInt().seconds

    override fun serialize(encoder: Encoder, value: Duration) {
        encoder.encodeInt(value.inWholeSeconds.toInt())
    }

}