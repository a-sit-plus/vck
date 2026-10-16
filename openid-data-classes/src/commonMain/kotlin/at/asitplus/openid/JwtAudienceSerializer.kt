package at.asitplus.openid

import kotlinx.serialization.builtins.SetSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonTransformingSerializer

/**
 * Serializes the claim `aud` ([RFC 7519 4.1.3](https://datatracker.ietf.org/doc/html/rfc7519#section-4.1.3)), which
 * is an array of strings, or a single string for one audience. Decodes both forms, encodes a single audience as
 * string.
 */
object JwtAudienceSerializer : JsonTransformingSerializer<Set<String>>(SetSerializer(String.serializer())) {

    override fun transformDeserialize(element: JsonElement): JsonElement =
        element as? JsonArray ?: JsonArray(listOf(element))

    override fun transformSerialize(element: JsonElement): JsonElement =
        (element as? JsonArray)?.singleOrNull() ?: element
}
