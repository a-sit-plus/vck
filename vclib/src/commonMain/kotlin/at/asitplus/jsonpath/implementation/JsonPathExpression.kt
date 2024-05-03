package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathQuery
import at.asitplus.jsonpath.core.JsonPathSelector


internal sealed interface JsonPathExpression {

    sealed class FilterExpression(
        val expressionType: JsonPathFilterExpressionType,
        open val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue,
    ) : JsonPathExpression {
        data class ValueExpression(
            override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.ValueTypeValue
        ) : FilterExpression(
            expressionType = JsonPathFilterExpressionType.ValueType,
            evaluate = evaluate
        )

        data class LogicalExpression(
            override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.LogicalTypeValue
        ) : FilterExpression(
            expressionType = JsonPathFilterExpressionType.LogicalType,
            evaluate = evaluate
        )

        sealed class NodesExpression(
            override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.NodesTypeValue
        ) : FilterExpression(
            expressionType = JsonPathFilterExpressionType.NodesType,
            evaluate = evaluate
        ) {
            sealed class FilterQueryExpression(
                open val jsonPathQuery: JsonPathQuery,
                override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.NodesTypeValue.FilterQueryResult
            ) : NodesExpression(evaluate) {
                data class SingularQueryExpression(
                    override val jsonPathQuery: JsonPathQuery,
                    override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.NodesTypeValue.FilterQueryResult.SingularQueryResult = {
                        val nodeList = jsonPathQuery.invoke(
                            currentNode = it.currentNode,
                            rootNode = it.rootNode,
                        ).map {
                            it.value
                        }
                        JsonPathFilterExpressionValue.NodesTypeValue.FilterQueryResult.SingularQueryResult(
                            nodeList
                        )
                    }
                ) : FilterQueryExpression(
                    jsonPathQuery = jsonPathQuery,
                    evaluate = evaluate,
                ) {
                    fun toValueTypeValue(): ValueExpression {
                        return ValueExpression { context ->
                            this.evaluate(context).nodeList.firstOrNull()?.let {
                                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(it)
                            } ?: JsonPathFilterExpressionValue.ValueTypeValue.Nothing
                        }
                    }
                }

                data class NonSingularQueryExpression(
                    override val jsonPathQuery: JsonPathQuery,
                    override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.NodesTypeValue.FilterQueryResult.NonSingularQueryResult = {
                        val nodeList = jsonPathQuery.invoke(
                            currentNode = it.currentNode,
                            rootNode = it.rootNode,
                        ).map {
                            it.value
                        }
                        JsonPathFilterExpressionValue.NodesTypeValue.FilterQueryResult.NonSingularQueryResult(
                            nodeList
                        )
                    }
                ) : FilterQueryExpression(
                    jsonPathQuery = jsonPathQuery,
                    evaluate = evaluate
                )
            }

            data class NodesFunctionExpression(
                override val evaluate: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.NodesTypeValue.FunctionExtensionResult
            ) : NodesExpression(evaluate)
        }
    }

    data class SelectorExpression(val selector: JsonPathSelector) : JsonPathExpression

    data object NoType : JsonPathExpression
    data object ErrorType : JsonPathExpression
}