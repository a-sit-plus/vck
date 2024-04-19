package at.asitplus.wallet.lib.data.jsonPath

sealed class JsonPathFunctionExtension<ReturnType : JsonPathExpressionValue>(
    val name: String,
    val argumentTypes: List<JsonPathExpressionTypeEnum>,
) {
    abstract fun invoke(arguments: List<JsonPathExpressionValue>): ReturnType
    fun validateArgumentTypes(arguments: List<JsonPathExpressionValue>) {
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
        argumentTypes: List<JsonPathExpressionTypeEnum>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.ValueTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class LogicalTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathExpressionTypeEnum>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.LogicalTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class NodesTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathExpressionTypeEnum>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.NodesTypeValue.FunctionExtensionResult>(
        name = name,
        argumentTypes = argumentTypes,
    )
}