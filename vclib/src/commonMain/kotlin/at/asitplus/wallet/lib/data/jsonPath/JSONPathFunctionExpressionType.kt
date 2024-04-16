package at.asitplus.wallet.lib.data.jsonPath

sealed interface JSONPathFunctionExpressionType {
    data object ValueType : JSONPathFunctionExpressionType

    data object LogicalType : JSONPathFunctionExpressionType

    data object NodesType : JSONPathFunctionExpressionType
}