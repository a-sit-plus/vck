package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser
import io.github.aakira.napier.Napier

val napierJSONPathErrorHandler by lazy {
    object : JSONPathErrorHandler {
        override fun unknownFunctionExtension(ctx: JSONPathParser.Function_exprContext) {
            Napier.e("Unknown JSONPath function extension: \"${ctx.FUNCTION_NAME().text}\"")
        }

        override fun invalidFunctionExtensionReturnTypeForTestExpression(ctx: JSONPathParser.Function_exprContext) {
            Napier.e("Invalid JSONPath function extension return type for test expression: \"${ctx.FUNCTION_NAME().text}\"")
        }

        override fun invalidFunctionExtensionReturnTypeForComparable(ctx: JSONPathParser.Function_exprContext) {
            Napier.e("Invalid JSONPath function extension return type for test expression: \"${ctx.FUNCTION_NAME().text}\"")
        }

        override fun invalidArglistForFunctionExtension(
            functionExtension: JSONPathFunctionExtension<*>,
            coercedArgumentTypes: List<JSONPathExpressionTypeEnum?>
        ) {
            Napier.e(
                "Invalid arguments for function extension \"${functionExtension.name}\": Expected: <${
                    functionExtension.argumentTypes.joinToString(
                        ", "
                    )
                }>, but received <${coercedArgumentTypes.joinToString(", ")}>"
            )
        }
    }
}