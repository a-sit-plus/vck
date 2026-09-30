package at.asitplus.openid

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

/** Accepts the CSC Bindings 7.1.2 `documentInfos` spelling and normalizes it to the Annex B field. */
object QesApprovalRequestSerializer :
    JsonTransformingSerializer<QesApprovalRequest>(QesApprovalRequest.generatedSerializer()) {

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject
        properties.forEach { (key, value) ->
            when (key) {
                "documentInfos" -> if ("documentDigests" !in properties) put("documentDigests", value)
                "documentDigests" -> put(key, normalizeDocuments(value))
                "type" -> Unit // consumed by the sealed TransactionData polymorphic serializer
                else -> put(key, value)
            }
        }
        if ("documentInfos" in properties && "documentDigests" in properties) {
            put("documentDigests", normalizeDocuments(properties.getValue("documentDigests")))
        }
    }

    private fun normalizeDocuments(element: JsonElement): JsonArray = JsonArray(element.jsonArray.map { entry ->
        val properties = entry.jsonObject
        buildJsonObject {
            properties.forEach { (key, value) ->
                // QES approval's newer checksum object has the same value as CSC's SRI checksum string.
                if (key == "checksum" && value is JsonObject) put(key, normalizeChecksum(value))
                else put(key, value)
            }
        }
    })

    private fun normalizeChecksum(checksum: JsonObject): JsonElement {
        val oid = checksum["algorithmOID"]?.toString()?.trim('"') ?: return checksum
        val digestName = when (oid) {
            "2.16.840.1.101.3.4.2.1" -> "sha256"
            "2.16.840.1.101.3.4.2.2" -> "sha384"
            "2.16.840.1.101.3.4.2.3" -> "sha512"
            else -> return checksum
        }
        val value = checksum["value"]?.toString()?.trim('"')?.trimEnd('=') ?: return checksum
        return kotlinx.serialization.json.JsonPrimitive("$digestName-$value")
    }
}
