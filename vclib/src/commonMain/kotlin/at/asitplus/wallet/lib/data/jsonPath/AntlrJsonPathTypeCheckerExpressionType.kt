package at.asitplus.wallet.lib.data.jsonPath

sealed class AntlrJsonPathTypeCheckerExpressionType(val jsonPathExpressionType: JsonPathExpressionType?) {
    object ValueType : AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.ValueType)

    object LogicalType : AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.LogicalType)

    sealed class NodesType :
        AntlrJsonPathTypeCheckerExpressionType(JsonPathExpressionType.NodesType) {
        sealed class FilterQuery : NodesType() {
            data object SingularQuery : FilterQuery()
            data object NonSingularQuery : FilterQuery()
        }

        data object FunctionNodesType : NodesType()
    }

    data object ErrorType : AntlrJsonPathTypeCheckerExpressionType(null)
}