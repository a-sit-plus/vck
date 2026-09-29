package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

/** Flattens either CSC document form into the qesApprovalRequest documentDigests array. */
object QesApprovalDocumentSerializer :
    JsonTransformingSerializer<QesApprovalDocument>(QesApprovalDocument.generatedSerializer()) {

    private val documentInfoKeys = DocumentInfo.serializer().descriptor.elementNames.toSet()
    private val documentReferenceKeys = DocumentReference.serializer().descriptor.elementNames.toSet()

    override fun transformSerialize(element: JsonElement): JsonElement = buildJsonObject {
        element.jsonObject.values.forEach { component ->
            component.jsonObject.forEach { (key, value) -> put(key, value) }
        }
    }

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject
        when {
            "hash" in properties -> put(
                QesApprovalDocument::documentInfo.name,
                JsonObject(properties.filterKeys(documentInfoKeys::contains)),
            )

            "href" in properties -> put(
                QesApprovalDocument::documentReference.name,
                JsonObject(properties.filterKeys(documentReferenceKeys::contains)),
            )

            else -> throw SerializationException("CSC approval document must contain either hash or href")
        }
    }
}
