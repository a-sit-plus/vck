package at.asitplus.wallet.lib.data.jsonPath

interface AntlrJsonPathTypeCheckerErrorListener {
    fun unknownFunctionExtension(functionExtensionName: String)

    // section 2.4.3: Well-Typedness of Function Expressions
    // https://datatracker.ietf.org/doc/rfc9535/ from 2024-02
    fun invalidFunctionExtensionForTestExpression(functionExtensionName: String)

    fun invalidFunctionExtensionForComparable(functionExtensionName: String)

    fun invalidArglistForFunctionExtension(
        functionExtension: JsonPathFunctionExtension<*>,
        coercedArgumentTypes: List<JsonPathExpressionType?>
    )
}