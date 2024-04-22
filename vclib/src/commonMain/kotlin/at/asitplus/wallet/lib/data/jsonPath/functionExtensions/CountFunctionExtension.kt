package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionType
import at.asitplus.wallet.lib.data.jsonPath.JsonPathFunctionExtension
import kotlinx.serialization.json.JsonPrimitive

data object CountFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "count",
    argumentTypes = listOf(
        JsonPathExpressionType.NodesType,
    )
) {
    override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JsonPathExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JsonPathExpressionValue.NodesTypeValue): JsonPathExpressionValue.ValueTypeValue {
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(nodesTypeValue.nodeList.size.toUInt())
        )
    }
}