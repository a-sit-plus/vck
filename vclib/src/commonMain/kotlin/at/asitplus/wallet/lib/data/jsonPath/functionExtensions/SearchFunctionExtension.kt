package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionType
import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JsonPathFunctionExtension
import kotlinx.serialization.json.JsonPrimitive


data object SearchFunctionExtension : JsonPathFunctionExtension.LogicalTypeFunctionExtension(
    name = "search",
    argumentTypes = listOf(
        JsonPathExpressionType.ValueType,
        JsonPathExpressionType.ValueType,
    )
) {
    override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.LogicalTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            stringArgument = arguments[0] as JsonPathExpressionValue.ValueTypeValue,
            regexArgument = arguments[1] as JsonPathExpressionValue.ValueTypeValue,
        )
    }

    private fun implementation(
        stringArgument: JsonPathExpressionValue.ValueTypeValue,
        regexArgument: JsonPathExpressionValue.ValueTypeValue,
    ): JsonPathExpressionValue.LogicalTypeValue {
        if(stringArgument !is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }
        if(regexArgument !is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }

        val stringElement = stringArgument.jsonElement
        val regexElement = regexArgument.jsonElement

        if (stringElement !is JsonPrimitive) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }
        if (regexElement !is JsonPrimitive) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }

        if (stringElement.isString != true) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }
        if (regexElement.isString != true) {
            return JsonPathExpressionValue.LogicalTypeValue(false)
        }

        val isMatch = try {
            // TODO: check assumption that Regex supports RFC9485:
            //  https://www.rfc-editor.org/rfc/rfc9485.html
            Regex(regexElement.content).containsMatchIn(stringElement.content)
        } catch (throwable: Throwable) {
            false
        }

        return JsonPathExpressionValue.LogicalTypeValue(isMatch)
    }
}