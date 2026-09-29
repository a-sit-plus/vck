package at.asitplus.csc.datamodel.requests

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.basic.SigningAlgorithm
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.csc.datamodel.documents.DocumentRepresentations
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

/**
 * Flattens a [SignatureCreationRequest] into its CSC JSON union and reconstructs its component objects when decoding.
 */
object SignatureCreationRequestSerializer :
    JsonTransformingSerializer<SignatureCreationRequest>(SignatureCreationRequest.generatedSerializer()) {
    private val documentKeys = listOf(
        DocumentData.serializer(),
        DocumentReference.serializer(),
        DocumentRepresentations.serializer(),
    ).flatMap { it.descriptor.elementNames }.toSet()

    private val adesKeys = AdesParameters.serializer().descriptor.elementNames.toSet()

    private val signingAlgorithmKeys = SigningAlgorithm.serializer().descriptor.elementNames.toSet()

    override fun transformSerialize(element: JsonElement): JsonElement = buildJsonObject {
        element.jsonObject.values.forEach { component ->
            component.jsonObject.forEach { (key, value) ->
                put(key, value)
            }
        }
    }

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject

        put(
            SignatureCreationRequest::document.name,
            JsonObject(properties.filterKeys(documentKeys::contains)),
        )
        put(
            SignatureCreationRequest::adesParameters.name,
            JsonObject(properties.filterKeys(adesKeys::contains)),
        )
        put(
            SignatureCreationRequest::signingAlgorithm.name,
            JsonObject(properties.filterKeys(signingAlgorithmKeys::contains)),
        )
    }
}
