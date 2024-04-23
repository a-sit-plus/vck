package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive

interface Rfc8259Utils {
    companion object {
        fun unpackStringLiteral(string: String): String {
            return Json.decodeFromString<JsonPrimitive>(string).content
        }

        fun escapeToDoubleQuotedString(string: String): String {
            return Json.encodeToString(JsonPrimitive(string))
        }
    }
}