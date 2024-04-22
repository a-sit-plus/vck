package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionType
import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JsonPathFunctionExtension


data object ValueFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "value",
    argumentTypes = listOf(
        JsonPathExpressionType.NodesType,
    )
) {
    override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            nodesTypeValue = arguments[0] as JsonPathExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JsonPathExpressionValue.NodesTypeValue): JsonPathExpressionValue.ValueTypeValue {
        return if (nodesTypeValue.nodeList.size == 1) {
            JsonPathExpressionValue.ValueTypeValue.JsonValue(nodesTypeValue.nodeList[0])
        } else JsonPathExpressionValue.ValueTypeValue.Nothing
    }
}