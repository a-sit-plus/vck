package at.asitplus.jsonpath.core.functionExtensions

import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.4.4.  length() Function Extension
 */
@OptIn(ExperimentalSerializationApi::class)
internal data object LengthFunctionExtension : JsonPathFunctionExtension.ValueTypeFunctionExtension(
    name = "length",
    argumentTypes = listOf(
        JsonPathFilterExpressionType.ValueType,
    )
) {
    override fun invoke(arguments: List<JsonPathFilterExpressionValue>): JsonPathFilterExpressionValue.ValueTypeValue {
        super.validateArgumentTypes(arguments)
        return implementation(
            arguments[0] as JsonPathFilterExpressionValue.ValueTypeValue
        )
    }

    private fun implementation(argument: JsonPathFilterExpressionValue.ValueTypeValue): JsonPathFilterExpressionValue.ValueTypeValue {
        if (argument !is JsonPathFilterExpressionValue.ValueTypeValue.JsonValue) {
            return JsonPathFilterExpressionValue.ValueTypeValue.Nothing
        }
        return when (argument.jsonElement) {
            is JsonArray -> JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonObject -> JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                JsonPrimitive(argument.jsonElement.size.toUInt())
            )

            is JsonPrimitive -> if (argument.jsonElement.isString) {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(
                        run {
                            val codePoints =
                                argument.jsonElement.content.count() + argument.jsonElement.content.count {
                                    it.code > 0xffff
                                }
                            codePoints.toUInt()
                        }
                    )
                )
            } else JsonPathFilterExpressionValue.ValueTypeValue.Nothing
        }
    }
}