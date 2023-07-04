package at.asitplus.wallet.lib.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object IsoSexEnumSerializer : KSerializer<IsoSexEnum?> {

    override val descriptor: SerialDescriptor =
        PrimitiveSerialDescriptor("IsoSexEnum?", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: IsoSexEnum?) {
        value?.let { encoder.encodeInt(it.code) }
    }

    override fun deserialize(decoder: Decoder): IsoSexEnum? {
        return IsoSexEnum.parseCode(decoder.decodeInt())
    }

}
