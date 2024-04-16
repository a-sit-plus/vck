package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

interface JSONPathTypeCheckerErrorHandler {
    fun unknownFunctionExtension(ctx: JSONPathParser.Function_exprContext)

    /* section 2.4.3.1 of https://datatracker.ietf.org/doc/rfc9535/ from 2024-02
    For a function expression to be well-typed:
    1.  Its declared type must be well-typed in the context in which it
       occurs.

       As a test-expr in a logical expression:
          The function's declared result type is LogicalType or (giving
          rise to conversion as per Section 2.4.2) NodesType.

       As a comparable in a comparison:
          The function's declared result type is ValueType.

       As a function-argument in another function expression:
          The function's declared result type fulfills the following
          rules for the corresponding parameter of the enclosing
          function.
     */
    fun invalidFunctionExtensionReturnTypeForTestExpression(ctx: JSONPathParser.Function_exprContext)
    fun invalidFunctionExtensionReturnTypeForComparable(ctx: JSONPathParser.Function_exprContext)
    fun invalidFunctionExtensionReturnTypeForFunctionArgumentType(ctx: JSONPathParser.Function_exprContext, expectedArgumentType: JSONPathFunctionExpressionType)
}