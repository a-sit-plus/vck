package at.asitplus.wallet.lib.iso

import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder

object NamespacedIssuerSignedListSerializer : KSerializer<Map<String, IssuerSignedList>> {

    private val mapSerializer = MapSerializer(String.serializer(), object : IssuerSignedListSerializer("") {})

    override val descriptor = mapSerializer.descriptor

    override fun deserialize(decoder: Decoder): Map<String, IssuerSignedList> = NamespacedMapEntryDeserializer().let {
        MapSerializer(it.namespaceSerializer, it.itemSerializer).deserialize(decoder)
    }

    class NamespacedMapEntryDeserializer {
        lateinit var key: String

        val namespaceSerializer = NamespaceSerializer()
        val itemSerializer = IssuerSignedListSerializer()

        inner class NamespaceSerializer internal constructor() : KSerializer<String> {
            override val descriptor = PrimitiveSerialDescriptor("ISO namespace", PrimitiveKind.STRING)

            override fun deserialize(decoder: Decoder): String = decoder.decodeString().apply { key = this }

            override fun serialize(encoder: Encoder, value: String) {
                encoder.encodeString(value).also { key = value }
            }

        }

        inner class IssuerSignedListSerializer internal constructor() : KSerializer<IssuerSignedList> {
            override val descriptor = mapSerializer.descriptor

            override fun deserialize(decoder: Decoder): IssuerSignedList =
                decoder.decodeSerializableValue(IssuerSignedListSerializer(key))


            override fun serialize(encoder: Encoder, value: IssuerSignedList) {
                encoder.encodeSerializableValue(IssuerSignedListSerializer(key), value)
            }

        }
    }

    override fun serialize(encoder: Encoder, value: Map<String, IssuerSignedList>) =
        NamespacedMapEntryDeserializer().let {
            MapSerializer(it.namespaceSerializer, it.itemSerializer).serialize(encoder, value)
        }

}