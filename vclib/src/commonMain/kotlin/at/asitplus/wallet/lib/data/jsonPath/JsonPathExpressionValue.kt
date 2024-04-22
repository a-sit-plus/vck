package at.asitplus.wallet.lib.data.jsonPath

import kotlinx.serialization.json.JsonElement

sealed interface JsonPathExpressionValue {
    val expressionType: JsonPathExpressionType

    sealed class ValueTypeValue : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.ValueType
        override fun toString(): String {
            return "ValueTypeValue"
        }

        class JsonValue(val jsonElement: JsonElement) : ValueTypeValue() {
            override fun toString(): String {
                return "${super.toString()}($jsonElement)"
            }
        }
        data object Nothing : ValueTypeValue() {
            override fun toString(): String {
                return "${super.toString()}(Nothing)"
            }
        }
    }

    class LogicalTypeValue(val isTrue: Boolean) : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.LogicalType

        override fun toString(): String {
            return "LogicalTypeValue($isTrue)"
        }
    }

    sealed class NodesTypeValue(val nodeList: List<JsonElement>) : JsonPathExpressionValue {
        override val expressionType: JsonPathExpressionType = JsonPathExpressionType.NodesType

        override fun toString(): String {
            return "NodesTypeValue[${nodeList.joinToString(", ")}]"
        }

        class SingularQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FilterQueryResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
        class FunctionExtensionResult(nodeList: List<JsonElement>): NodesTypeValue(nodeList)
    }
}