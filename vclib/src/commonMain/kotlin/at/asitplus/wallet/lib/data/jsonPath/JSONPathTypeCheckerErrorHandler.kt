package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

interface JSONPathTypeCheckerErrorHandler {
    fun unknownFunctionExtension(ctx: JSONPathParser.Function_exprContext)

    // section 2.4.3: Well-Typedness of Function Expressions
    // https://datatracker.ietf.org/doc/rfc9535/ from 2024-02
    fun invalidFunctionExtensionReturnTypeForTestExpression(ctx: JSONPathParser.Function_exprContext)
    fun invalidFunctionExtensionReturnTypeForComparable(ctx: JSONPathParser.Function_exprContext)

    fun invalidArglistForFunctionExtension(functionExtension: JSONPathFunctionExtension<*>, coercedArgumentTypes: List<JSONPathExpressionTypeEnum?>)
}