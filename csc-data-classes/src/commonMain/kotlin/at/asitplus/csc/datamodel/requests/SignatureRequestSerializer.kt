package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

/** Flattens a [SignatureRequest] into its CSC JSON union and reconstructs its component objects when decoding. */
object SignatureRequestSerializer :
    JsonTransformingSerializer<SignatureRequest>(SignatureRequest.generatedSerializer()) {
    private val documentKeys = listOf(
        DocumentData.serializer(),
        DocumentReference.serializer(),
    ).flatMap { it.descriptor.elementNames }.toSet()

    private val adesKeys = AdesParameters.serializer().descriptor.elementNames.toSet()

    override fun transformSerialize(element: JsonElement): JsonElement = buildJsonObject {
        element.jsonObject.forEach { (propertyName, propertyValue) ->
            if (propertyName == SignatureRequest::document.name ||
                propertyName == SignatureRequest::adesParameters.name
            ) {
                propertyValue.jsonObject.forEach { (key, value) ->
                    put(key, value)
                }
            } else {
                put(propertyName, propertyValue)
            }
        }
    }

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject

        put(
            SignatureRequest::document.name,
            JsonObject(properties.filterKeys(documentKeys::contains)),
        )
        put(
            SignatureRequest::adesParameters.name,
            JsonObject(properties.filterKeys(adesKeys::contains)),
        )
        properties[SignatureRequest::signatureQualifier.name]?.let {
            put(SignatureRequest::signatureQualifier.name, it)
        }
        properties[RESPONSE_URI]?.let { put(RESPONSE_URI, it) }
    }

    private const val RESPONSE_URI = "responseURI"
}
