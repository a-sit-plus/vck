package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

sealed interface JSONPathFunctionExpressionValue {
    sealed interface ValueTypeValue : JSONPathFunctionExpressionValue {
        class JsonValue(val jsonElement: JsonElement) : ValueTypeValue
        data object Nothing : ValueTypeValue
    }

    class LogicalTypeValue(val isTrue: Boolean) : JSONPathFunctionExpressionValue

    class NodesTypeValue(val nodeList: List<JsonElement>) : JSONPathFunctionExpressionValue

    fun toExpressionType(): JSONPathFunctionExpressionType {
        return when(this) {
            ValueTypeValue.Nothing -> JSONPathFunctionExpressionType.ValueType
            is ValueTypeValue.JsonValue -> JSONPathFunctionExpressionType.ValueType
            is LogicalTypeValue -> JSONPathFunctionExpressionType.LogicalType
            is NodesTypeValue -> JSONPathFunctionExpressionType.NodesType
        }
    }
}