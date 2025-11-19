package at.asitplus.wallet.lib.data.iso18013

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

@Serializable(with = IdentifierInfo.Serializer::class)
data class IdentifierInfo(
    val keys: Map<IdentifierInfoKey, RFU> = emptyMap(),
) {
    object Serializer : KSerializer<IdentifierInfo> {

        private val delegate: KSerializer<Map<IdentifierInfoKey, RFU>> =
            MapSerializer(IdentifierInfoKey.Serializer, RFU.serializer())

        override val descriptor: SerialDescriptor = delegate.descriptor

        override fun serialize(encoder: Encoder, value: IdentifierInfo) {
            encoder.encodeSerializableValue(delegate, value.keys)
        }

        override fun deserialize(decoder: Decoder): IdentifierInfo {
            val map = decoder.decodeSerializableValue(delegate)
            return IdentifierInfo(map)
        }
    }
}