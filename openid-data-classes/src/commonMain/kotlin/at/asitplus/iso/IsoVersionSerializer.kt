package at.asitplus.iso

import io.github.z4kn4fein.semver.Version
import io.github.z4kn4fein.semver.toVersion
import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

/** For [Version], but skips patch, i.e. serializes `1.1` instead of `1.1.0` */
object IsoVersionSerializer : KSerializer<Version> {
    override fun deserialize(decoder: Decoder): Version = decoder.decodeString().toVersion(strict = false)

    override fun serialize(
        encoder: Encoder,
        value: Version,
    ): Unit {
        encoder.encodeString(value.toIsoString())
    }

    override val descriptor: SerialDescriptor = PrimitiveSerialDescriptor("LooseVersion", PrimitiveKind.STRING)
}

/** Skips patch if it is 0, i.e. serializes `1.1` instead of `1.1.0` */
fun Version.toIsoString(): String = if (patch == 0 && preRelease == null && buildMetadata == null)
    "${major}.${minor}"
else
    toString()
