package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionTypeEnum
import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JSONPathFunctionExtension
import kotlinx.serialization.json.JsonPrimitive

data object CountFunctionExtension : JSONPathFunctionExtension.ValueTypeFunctionExtension(
    name = "count",
    argumentTypes = listOf(
        JSONPathExpressionTypeEnum.NodesType,
    )
) {
    override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JSONPathExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JSONPathExpressionValue.NodesTypeValue): JSONPathExpressionValue.ValueTypeValue {
        return JSONPathExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(nodesTypeValue.nodeList.size.toUInt())
        )
    }
}