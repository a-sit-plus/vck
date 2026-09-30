package at.asitplus.csc.bindings

import at.asitplus.csc.datamodel.documents.DocumentInfo
import at.asitplus.csc.datamodel.documents.DocumentReference
import at.asitplus.signum.indispensable.Digest
import kotlinx.serialization.SerializationException
import kotlinx.serialization.descriptors.elementNames
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Applies the CSC Data Model Bindings 7.1 and TS 119 432 Annex B.6.2 document union on the wire. */
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
        if ("hash" in properties) put(
                QesApprovalDocument::documentInfo.name,
                JsonObject(properties.filterKeys(documentInfoKeys::contains)),
            )
        if ("href" in properties) {
            val reference = properties.filterKeys(documentReferenceKeys::contains).toMutableMap()
            val checksum = properties["checksum"] as? JsonObject
            if (checksum != null) {
                val oid = checksum["algorithmOID"]?.jsonPrimitive?.content
                    ?: throw SerializationException("Approval document checksum requires algorithmOID")
                val value = checksum["value"]?.jsonPrimitive?.content
                    ?: throw SerializationException("Approval document checksum requires value")
                val digest = Digest.entries.firstOrNull { it.oid.toString() == oid }
                    ?: throw SerializationException("Unsupported approval document checksum algorithm $oid")
                reference["checksum"] = JsonPrimitive(
                    "${digest.name.lowercase()}-${value.trimEnd('=')}"
                )
            }
            put(
                QesApprovalDocument::documentReference.name,
                JsonObject(reference),
            )
        }
        if ("hash" !in properties && "href" !in properties)
            throw SerializationException("CSC approval document must contain hash or href")
    }
}
