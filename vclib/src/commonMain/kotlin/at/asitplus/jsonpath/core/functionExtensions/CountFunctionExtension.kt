package at.asitplus.wallet.lib.data.jsonpath.functionExtensions

import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonPrimitive

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.4.5.  count() Function Extension
 */
@OptIn(ExperimentalSerializationApi::class)
internal data object CountFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "count",
    argumentTypes = listOf(
        JsonPathFilterExpressionType.NodesType,
    )
) {
    override fun invoke(arguments: List<JsonPathFilterExpressionValue>): JsonPathFilterExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JsonPathFilterExpressionValue.NodesTypeValue
        )
    }

    private fun implementation(nodesTypeValue: JsonPathFilterExpressionValue.NodesTypeValue): JsonPathFilterExpressionValue.ValueTypeValue {
        return JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(nodesTypeValue.nodeList.size.toUInt())
        )
    }
}