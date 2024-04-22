package at.asitplus.wallet.lib.data.jsonPath

sealed class JsonPathFunctionExtension<ReturnType : JsonPathExpressionValue>(
    val name: String,
    val argumentTypes: List<JsonPathExpressionType>,
) {
    abstract fun invoke(arguments: List<JsonPathExpressionValue>): ReturnType
    fun validateArgumentTypes(arguments: List<JsonPathExpressionValue>) {
        val isNotArgumentsMatching =
            (arguments.size != argumentTypes.size) or arguments.zip(argumentTypes).any {
                it.first.expressionType != it.second
            }
        if (isNotArgumentsMatching) {
            throw InvalidFunctionExtensionArgumentsException(
                functionExtension = this,
                actualArguments = arguments
            )
        }
    }

    abstract class ValueTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.ValueTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class LogicalTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.LogicalTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class NodesTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathExpressionValue.NodesTypeValue.FunctionExtensionResult>(
        name = name,
        argumentTypes = argumentTypes,
    )
}

class InvalidFunctionExtensionArgumentsException(
    val functionExtension: JsonPathFunctionExtension<*>,
    val actualArguments: List<JsonPathExpressionValue>
) : Exception(
    "Invalid arguments for function extension \"${functionExtension.name}\": Expected: <${
        functionExtension.argumentTypes.joinToString(", ")
    }>, but received <${actualArguments.map { it.expressionType }.joinToString(", ")}>: <${actualArguments.joinToString(", ")}>"
)