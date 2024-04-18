package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionTypeEnum
import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JSONPathFunctionExtension
import kotlinx.serialization.json.JsonPrimitive


data object SearchFunctionExtension : JSONPathFunctionExtension.LogicalTypeFunctionExtension(
    name = "search",
    argumentTypes = listOf(
        JSONPathExpressionTypeEnum.ValueType,
        JSONPathExpressionTypeEnum.ValueType,
    )
) {
    override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue.LogicalTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            stringArgument = arguments[0] as JSONPathExpressionValue.ValueTypeValue,
            regexArgument = arguments[1] as JSONPathExpressionValue.ValueTypeValue,
        )
    }

    private fun implementation(
        stringArgument: JSONPathExpressionValue.ValueTypeValue,
        regexArgument: JSONPathExpressionValue.ValueTypeValue,
    ): JSONPathExpressionValue.LogicalTypeValue {
        if(stringArgument !is JSONPathExpressionValue.ValueTypeValue.JsonValue) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }
        if(regexArgument !is JSONPathExpressionValue.ValueTypeValue.JsonValue) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }

        val stringElement = stringArgument.jsonElement
        val regexElement = regexArgument.jsonElement

        if (stringElement !is JsonPrimitive) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }
        if (regexElement !is JsonPrimitive) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }

        if (stringElement.isString != true) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }
        if (regexElement.isString != true) {
            return JSONPathExpressionValue.LogicalTypeValue(false)
        }

        val isMatch = try {
            // TODO: check assumption that Regex supports RFC9485:
            //  https://www.rfc-editor.org/rfc/rfc9485.html
            Regex(regexElement.content).containsMatchIn(stringElement.content)
        } catch (throwable: Throwable) {
            false
        }

        return JSONPathExpressionValue.LogicalTypeValue(isMatch)
    }
}