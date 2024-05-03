package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFunctionExtension

interface AntlrJsonPathSemanticAnalyzerErrorListener {
    fun unknownFunctionExtension(functionExtensionName: String)

    /**
     * specification: https://datatracker.ietf.org/doc/rfc9535/
     * date: 2024-02
     * section 2.4.3: Well-Typedness of Function Expressions
     */
    fun invalidFunctionExtensionForTestExpression(functionExtensionName: String)

    fun invalidFunctionExtensionForComparable(functionExtensionName: String)

    fun invalidArglistForFunctionExtension(
        functionExtension: JsonPathFunctionExtension<*>,
        coercedArgumentTypes: List<Pair<JsonPathFilterExpressionType?, String>>
    )

    fun invalidTestExpression(
        testContextString: String
    )
}