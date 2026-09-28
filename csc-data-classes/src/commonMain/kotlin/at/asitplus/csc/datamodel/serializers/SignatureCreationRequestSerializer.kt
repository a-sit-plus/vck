package at.asitplus.csc.datamodel.serializers

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.requests.SignatureCreationRequest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject

object SignatureCreationRequestSerializer : FlatteningSerializerTemplate<SignatureCreationRequest>(
    "at.asitplus.csc.datamodel.requests.SignatureCreationRequest"
) {
    override fun serializeFlattened(json: Json, value: SignatureCreationRequest): JsonObject = buildMap<String, JsonElement> {
        putAll(json.encodeCreationDocument(value.document))
        addObject(json, AdesParameters.serializer(), value.adesParameters)
        addObject(json, SigningAlgorithm.serializer(), value.signingAlgorithm)
    }.let(::JsonObject)

    override fun deserializeFlattened(json: Json, properties: JsonObject): SignatureCreationRequest =
        SignatureCreationRequest(
            document = properties.decodeCreationDocument(json),
            adesParameters = json.decodeFiltered(AdesParameters.serializer(), properties, ADES_KEYS),
            signingAlgorithm = json.decodeFiltered(SigningAlgorithm.serializer(), properties, SIGNING_KEYS),
        )
}
