package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

sealed interface JSONPathExpressionValue {
    val expressionType: JSONPathExpressionTypeEnum

    sealed class ValueTypeValue : JSONPathExpressionValue {
        override val expressionType: JSONPathExpressionTypeEnum = JSONPathExpressionTypeEnum.ValueType

        class JsonValue(val jsonElement: JsonElement) : ValueTypeValue()
        data object Nothing : ValueTypeValue()
    }

    class LogicalTypeValue(val isTrue: Boolean) : JSONPathExpressionValue {
        override val expressionType: JSONPathExpressionTypeEnum = JSONPathExpressionTypeEnum.LogicalType
    }

    sealed class NodesTypeValue(val nodeList: List<JsonElement>) : JSONPathExpressionValue {
        override val expressionType: JSONPathExpressionTypeEnum = JSONPathExpressionTypeEnum.NodesType

        class SingularQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FilterQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FunctionExtensionResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
    }
}