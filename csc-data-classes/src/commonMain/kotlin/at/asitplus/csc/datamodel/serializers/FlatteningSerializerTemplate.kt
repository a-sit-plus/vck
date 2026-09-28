package at.asitplus.csc.datamodel.serializers

import kotlinx.serialization.KSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject

/** Base for CSC serializers whose wire object is the merged JSON representation of several values. */
abstract class FlatteningSerializerTemplate<T>(serialName: String) : KSerializer<T> {
    final override val descriptor: SerialDescriptor = buildClassSerialDescriptor(serialName)

    final override fun serialize(encoder: Encoder, value: T) {
        val jsonEncoder = encoder.requireJsonEncoder()
        jsonEncoder.encodeJsonElement(serializeFlattened(jsonEncoder.json, value))
    }

    final override fun deserialize(decoder: Decoder): T {
        val jsonDecoder = decoder.requireJsonDecoder()
        val properties = jsonDecoder.decodeJsonElement().jsonObject
        return deserializeFlattened(jsonDecoder.json, properties)
    }

    protected abstract fun serializeFlattened(json: Json, value: T): JsonObject

    protected abstract fun deserializeFlattened(json: Json, properties: JsonObject): T
}
