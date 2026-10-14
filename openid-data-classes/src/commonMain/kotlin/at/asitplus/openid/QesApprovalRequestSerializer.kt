package at.asitplus.openid

import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonTransformingSerializer
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject

/** Normalizes the CSC Bindings `documentInfos` spelling to Annex B `documentDigests`, preserving TS Hash objects. */
object QesApprovalRequestSerializer :
    JsonTransformingSerializer<QesApprovalRequest>(QesApprovalRequest.generatedSerializer()) {

    override fun transformDeserialize(element: JsonElement): JsonElement = buildJsonObject {
        val properties = element.jsonObject
        properties.forEach { (key, value) ->
            when (key) {
                "documentInfos" -> if ("documentDigests" !in properties) put("documentDigests", value)
                "documentDigests" -> put(key, value)
                "type" -> Unit // consumed by the sealed TransactionData polymorphic serializer
                else -> put(key, value)
            }
        }
        if ("documentInfos" in properties && "documentDigests" in properties) {
            put("documentDigests", properties.getValue("documentDigests"))
        }
    }
}
