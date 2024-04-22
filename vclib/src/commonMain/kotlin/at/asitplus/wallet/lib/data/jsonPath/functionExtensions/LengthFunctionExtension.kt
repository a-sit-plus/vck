package at.asitplus.wallet.lib.data.jsonPath.functionExtensions

import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionType
import at.asitplus.wallet.lib.data.jsonPath.JsonPathExpressionValue
import at.asitplus.wallet.lib.data.jsonPath.JsonPathFunctionExtension
import com.strumenta.antlrkotlin.runtime.ext.codePointIndices
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data object LengthFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "length",
    argumentTypes = listOf(
        JsonPathExpressionType.ValueType,
    )
) {
    override fun invoke(arguments: List<JsonPathExpressionValue>): JsonPathExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JsonPathExpressionValue.ValueTypeValue
        )
    }

    private fun implementation(argument: JsonPathExpressionValue.ValueTypeValue): JsonPathExpressionValue.ValueTypeValue {
        if (argument !is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
            return JsonPathExpressionValue.ValueTypeValue.Nothing
        }
        return when (argument.jsonElement) {
            is JsonArray -> JsonPathExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonObject -> JsonPathExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonPrimitive -> if (argument.jsonElement.isString) {
                JsonPathExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(argument.jsonElement.content.codePointIndices().size.toUInt())
                )
            } else JsonPathExpressionValue.ValueTypeValue.Nothing
        }
    }
}