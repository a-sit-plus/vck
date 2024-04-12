package at.asitplus.wallet.lib.data.JSONPath

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull

sealed class JSONPathFilterValue {
    object Nothing : JSONPathFilterValue()
    object NullValue : JSONPathFilterValue()
    class LogicalValue(val isTrue: Boolean) : JSONPathFilterValue()
    class NodeListValue(val nodeList: List<JsonElement>) : JSONPathFilterValue()
    class StringValue(val string: String) : JSONPathFilterValue()
    sealed class NumberValue : JSONPathFilterValue() {
        // TODO: support other number formats?
        class DoubleValue(val double: Double) : NumberValue() {
            override operator fun compareTo(other: NumberValue): Int = when (other) {
                is DoubleValue -> this.double.compareTo(other.double)
                is LongValue -> this.double.compareTo(other.long)
            }
        }

        class LongValue(val long: Long) : NumberValue() {
            override operator fun compareTo(other: NumberValue): Int = when (other) {
                is DoubleValue -> this.long.compareTo(other.double)
                is LongValue -> this.long.compareTo(other.long)
            }
        }

        abstract operator fun compareTo(other: NumberValue): Int
    }

    class JsonObjectValue(val jsonObject: JsonObject) : JSONPathFilterValue()
    class JsonArrayValue(val jsonArray: JsonArray) : JSONPathFilterValue()
}

internal fun JsonElement.toJSONPathFilterValue(): JSONPathFilterValue {
    return when (this) {
        is JsonArray -> JSONPathFilterValue.JsonArrayValue(this)
        is JsonObject -> JSONPathFilterValue.JsonObjectValue(this)
        is JsonPrimitive -> if (this.isString) {
            JSONPathFilterValue.StringValue(this.content)
        } else this.booleanOrNull?.let {
            JSONPathFilterValue.LogicalValue(it)
        } ?: this.doubleOrNull!!.let {
            // TODO: support other number formats like Long
            JSONPathFilterValue.NumberValue.DoubleValue(it)
        }

        JsonNull -> JSONPathFilterValue.NullValue
    }
}