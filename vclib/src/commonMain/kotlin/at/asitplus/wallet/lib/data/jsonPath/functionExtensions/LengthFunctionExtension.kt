package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionTypeEnum
import at.asitplus.wallet.lib.data.jsonPath.JSONPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JSONPathFunctionExtension
import com.strumenta.antlrkotlin.runtime.ext.codePointIndices
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data object LengthFunctionExtension : JSONPathFunctionExtension.ValueTypeFunctionExtension(
    name = "length",
    argumentTypes = listOf(
        JSONPathExpressionTypeEnum.ValueType,
    )
) {
    override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JSONPathExpressionValue.ValueTypeValue
        )
    }

    private fun implementation(argument: JSONPathExpressionValue.ValueTypeValue): JSONPathExpressionValue.ValueTypeValue {
        if (argument !is JSONPathExpressionValue.ValueTypeValue.JsonValue) {
            return JSONPathExpressionValue.ValueTypeValue.Nothing
        }
        return when (argument.jsonElement) {
            is JsonArray -> JSONPathExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonObject -> JSONPathExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonPrimitive -> if (argument.jsonElement.isString) {
                JSONPathExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(argument.jsonElement.content.codePointIndices().size.toUInt())
                )
            } else JSONPathExpressionValue.ValueTypeValue.Nothing
        }
    }
}