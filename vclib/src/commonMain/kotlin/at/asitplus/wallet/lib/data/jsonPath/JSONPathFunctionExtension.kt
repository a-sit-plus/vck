package at.asitplus.wallet.lib.data.jsonPath

sealed class JSONPathFunctionExtension<ReturnType : JSONPathExpressionValue>(
    val name: String,
    val argumentTypes: List<JSONPathExpressionTypeEnum>,
) {
    abstract fun invoke(arguments: List<JSONPathExpressionValue>): ReturnType
    fun validateArgumentTypes(arguments: List<JSONPathExpressionValue>) {
        if(arguments.size != argumentTypes.size) {
            throw InvalidArgumentsException(
                expectedArguments = argumentTypes.size,
                actualArguments = arguments.size,
            )
        }
        arguments.zip(argumentTypes).forEach {
            if (it.first.expressionType != it.second) {
                throw InvalidArgumentTypeException(
                    value = it.first,
                    expectedArgumentType = it.second,
                )
            }
        }
    }

    abstract class ValueTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathExpressionTypeEnum>,
    ) : JSONPathFunctionExtension<JSONPathExpressionValue.ValueTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class LogicalTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathExpressionTypeEnum>,
    ) : JSONPathFunctionExtension<JSONPathExpressionValue.LogicalTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class NodesTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathExpressionTypeEnum>,
    ) : JSONPathFunctionExtension<JSONPathExpressionValue.NodesTypeValue.FunctionExtensionResult>(
        name = name,
        argumentTypes = argumentTypes,
    )
}