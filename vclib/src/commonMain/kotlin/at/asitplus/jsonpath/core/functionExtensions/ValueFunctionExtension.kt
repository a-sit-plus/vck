package at.asitplus.jsonpath.core.functionExtensions

import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathFunctionExtension

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.4.8.  value() Function Extension
 */
internal data object ValueFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "value",
    argumentTypes = listOf(
        JsonPathFilterExpressionType.NodesType,
    )
) {
    override fun invoke(arguments: List<JsonPathFilterExpressionValue>): JsonPathFilterExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            nodesTypeValue = arguments[0] as JsonPathFilterExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JsonPathFilterExpressionValue.NodesTypeValue): JsonPathFilterExpressionValue.ValueTypeValue {
        return if (nodesTypeValue.nodeList.size == 1) {
            JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(nodesTypeValue.nodeList[0])
        } else JsonPathFilterExpressionValue.ValueTypeValue.Nothing
    }
}