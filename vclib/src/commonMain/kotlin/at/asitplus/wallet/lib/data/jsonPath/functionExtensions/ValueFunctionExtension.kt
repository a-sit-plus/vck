package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionTypeEnum
import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JSONPathFunctionExtension


data object ValueFunctionExtension : JSONPathFunctionExtension.ValueTypeFunctionExtension(
    name = "value",
    argumentTypes = listOf(
        JSONPathExpressionTypeEnum.NodesType,
    )
) {
    override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            nodesTypeValue = arguments[0] as JSONPathExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JSONPathExpressionValue.NodesTypeValue): JSONPathExpressionValue.ValueTypeValue {
        return if (nodesTypeValue.nodeList.size == 1) {
            JSONPathExpressionValue.ValueTypeValue.JsonValue(nodesTypeValue.nodeList[0])
        } else JSONPathExpressionValue.ValueTypeValue.Nothing
    }
}