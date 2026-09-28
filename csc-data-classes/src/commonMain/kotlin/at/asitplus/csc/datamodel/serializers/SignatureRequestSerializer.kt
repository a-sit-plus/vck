package at.asitplus.csc.datamodel.serializers

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SignatureQualifier
import at.asitplus.csc.datamodel.requests.SignatureRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

object SignatureRequestSerializer : FlatteningSerializerTemplate<SignatureRequest>(
    "at.asitplus.csc.datamodel.requests.SignatureRequest"
) {
    override fun serializeFlattened(json: Json, value: SignatureRequest): JsonObject = buildMap<String, JsonElement> {
        putAll(json.encodeRequestDocument(value.document))
        addObject(json, AdesParameters.serializer(), value.adesParameters)
        put(SIGNATURE_QUALIFIER, json.encodeToJsonElement(SignatureQualifier.serializer(), value.signatureQualifier))
        value.responseUri?.let { put(RESPONSE_URI, JsonPrimitive(it)) }
    }.let(::JsonObject)

    override fun deserializeFlattened(json: Json, properties: JsonObject): SignatureRequest {
        val signatureQualifier = properties[SIGNATURE_QUALIFIER]
            ?: throw kotlinx.serialization.SerializationException("Missing $SIGNATURE_QUALIFIER")

        return SignatureRequest(
            document = properties.decodeRequestDocument(json),
            adesParameters = json.decodeFiltered(AdesParameters.serializer(), properties, ADES_KEYS),
            signatureQualifier = json.decodeFromJsonElement(SignatureQualifier.serializer(), signatureQualifier),
            responseUri = properties[RESPONSE_URI]?.jsonPrimitive?.contentOrNull,
        )
    }
}
