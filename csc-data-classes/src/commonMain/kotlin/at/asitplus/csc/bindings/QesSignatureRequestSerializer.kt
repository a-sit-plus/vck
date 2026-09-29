package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.basic.AdesParameters
import at.asitplus.csc.datamodel.documents.DocumentData
import at.asitplus.csc.datamodel.documents.DocumentReference
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

/** Flattens a [at.asitplus.openid.QesSignatureRequest] into the CSC signatureRequest JSON object. */
object QesSignatureRequestSerializer :
    JsonTransformingSerializer<QesSignatureRequest>(QesSignatureRequest.generatedSerializer()) {

    private val documentKeys = listOf(
        DocumentData.serializer(),
        DocumentReference.serializer(),
    ).flatMap { it.descriptor.elementNames }.toSet()

    private val adesKeys = AdesParameters.serializer().descriptor.elementNames.toSet()

    override fun transformSerialize(element: JsonElement): JsonElement = buildJsonObject {
        element.jsonObject.forEach { (property, component) ->
            when (property) {
                QesSignatureRequest::document.name,
                QesSignatureRequest::adesParameters.name,
                    -> component.jsonObject.forEach { (key, value) -> put(key, value) }

                else -> put(property, component)
            }
        }
    }

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject
        put(
            QesSignatureRequest::document.name,
            JsonObject(properties.filterKeys(documentKeys::contains)),
        )
        put(
            QesSignatureRequest::adesParameters.name,
            JsonObject(properties.filterKeys(adesKeys::contains)),
        )
        val responseUriKey = QesSignatureRequest.serializer().descriptor.getElementName(2)
        properties[responseUriKey]?.let {
            put(responseUriKey, it)
        }
    }
}
