package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull

sealed interface JSONPathExpressionValue {
    class LogicalValue(val isTrue: Boolean) : JSONPathExpressionValue
    class NodeListValue(val nodeList: List<JsonElement>) : JSONPathExpressionValue

    sealed interface ValueTypeValue : JSONPathExpressionValue
    object Nothing : ValueTypeValue
    object NullValue : ValueTypeValue
    class StringValue(val string: String) : ValueTypeValue
    sealed class NumberValue : ValueTypeValue {
        class DoubleValue(val double: Double) : NumberValue() {
            override operator fun compareTo(other: NumberValue): Int = when (other) {
                is DoubleValue -> this.double.compareTo(other.double)
                is LongValue -> this.double.compareTo(other.long)
                is UIntValue -> this.double.compareTo(other.uInt.toLong())
            }
        }

        class LongValue(val long: Long) : NumberValue() {
            override operator fun compareTo(other: NumberValue): Int = when (other) {
                is DoubleValue -> this.long.compareTo(other.double)
                is LongValue -> this.long.compareTo(other.long)
                is UIntValue -> this.long.compareTo(other.uInt.toLong())
            }
        }

        class UIntValue(val uInt: UInt) : NumberValue() {
            override operator fun compareTo(other: NumberValue): Int = when (other) {
                is DoubleValue -> this.uInt.toDouble().compareTo(other.double)
                is LongValue -> this.uInt.toLong().compareTo(other.long)
                is UIntValue -> this.uInt.compareTo(other.uInt)
            }
        }

        abstract operator fun compareTo(other: NumberValue): Int
    }

    class JsonObjectValue(val jsonObject: JsonObject) : ValueTypeValue
    class JsonArrayValue(val jsonArray: JsonArray) : ValueTypeValue
}

internal fun JsonElement.toJSONPathFilterExpressionValue(): JSONPathExpressionValue {
    return when (this) {
        is JsonArray -> JSONPathExpressionValue.JsonArrayValue(this)
        is JsonObject -> JSONPathExpressionValue.JsonObjectValue(this)
        is JsonPrimitive -> if (this.isString) {
            JSONPathExpressionValue.StringValue(this.content)
        } else this.booleanOrNull?.let {
            JSONPathExpressionValue.LogicalValue(it)
        } ?: this.doubleOrNull!!.let {
            // TODO: maybe support other number formats like Long that don't fit into a double?
            JSONPathExpressionValue.NumberValue.DoubleValue(it)
        }

        JsonNull -> JSONPathExpressionValue.NullValue
    }
}