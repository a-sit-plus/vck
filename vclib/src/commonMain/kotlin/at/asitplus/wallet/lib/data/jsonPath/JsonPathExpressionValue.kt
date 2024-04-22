package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

sealed interface JsonPathExpressionValue {
    val expressionType: JsonPathExpressionType

    sealed class ValueTypeValue : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.ValueType

        class JsonValue(val jsonElement: JsonElement) : ValueTypeValue()
        data object Nothing : ValueTypeValue()
    }

    class LogicalTypeValue(val isTrue: Boolean) : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.LogicalType
    }

    sealed class NodesTypeValue(val nodeList: List<JsonElement>) : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.NodesType

        class SingularQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FilterQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FunctionExtensionResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
    }
}