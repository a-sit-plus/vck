package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull

sealed interface JSONPathFilterExpressionValue {
    object Nothing : JSONPathFilterExpressionValue
    class LogicalValue(val isTrue: Boolean) : JSONPathFilterExpressionValue
    class NodeListValue(val nodeList: List<JsonElement>) : JSONPathFilterExpressionValue

    sealed interface ValueTypeValue : JSONPathFilterExpressionValue
    object NullValue : ValueTypeValue
    class StringValue(val string: String) : ValueTypeValue
    sealed class NumberValue : ValueTypeValue {
        // TODO: support other number formats?
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

internal fun JsonElement.toJSONPathFilterExpressionValue(): JSONPathFilterExpressionValue {
    return when (this) {
        is JsonArray -> JSONPathFilterExpressionValue.JsonArrayValue(this)
        is JsonObject -> JSONPathFilterExpressionValue.JsonObjectValue(this)
        is JsonPrimitive -> if (this.isString) {
            JSONPathFilterExpressionValue.StringValue(this.content)
        } else this.booleanOrNull?.let {
            JSONPathFilterExpressionValue.LogicalValue(it)
        } ?: this.doubleOrNull!!.let {
            // TODO: maybe support other number formats like Long?
            JSONPathFilterExpressionValue.NumberValue.DoubleValue(it)
        }

        JsonNull -> JSONPathFilterExpressionValue.NullValue
    }
}