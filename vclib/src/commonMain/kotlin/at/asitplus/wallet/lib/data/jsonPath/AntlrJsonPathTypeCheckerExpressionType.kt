package at.asitplus.wallet.lib.data.jsonPath

sealed class AntlrJsonPathTypeCheckerExpressionType(val jsonPathExpressionType: JsonPathExpressionType?) {
    sealed class ValueType : AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.ValueType) {
        object LiteralValueType : ValueType()
    }

    object LogicalType : AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.LogicalType)

    sealed class NodesType :
        AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.NodesType) {
        sealed class FilterQuery : NodesType() {
            data object SingularQuery : FilterQuery()
            data object NonSingularQuery : FilterQuery()
        }

        data object FunctionNodesType : NodesType()
    }

    data object NoType : AntlrJsonPathTypeCheckerExpressionType(null)

    data object ErrorType : AntlrJsonPathTypeCheckerExpressionType(null)
}