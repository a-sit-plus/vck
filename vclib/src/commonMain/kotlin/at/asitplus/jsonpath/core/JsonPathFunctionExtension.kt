package at.asitplus.jsonpath.core

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section: 2.4.  Function Extensions
 */
sealed class JsonPathFunctionExtension<ReturnType : JsonPathFilterExpressionValue>(
    val name: String,
    val argumentTypes: List<JsonPathFilterExpressionType>,
) {
    abstract fun invoke(arguments: List<JsonPathFilterExpressionValue>): ReturnType
    fun validateArgumentTypes(arguments: List<JsonPathFilterExpressionValue>) {
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
        argumentTypes: List<JsonPathFilterExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathFilterExpressionValue.ValueTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class LogicalTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathFilterExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathFilterExpressionValue.LogicalTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class NodesTypeFunctionExtension(
        name: String,
        argumentTypes: List<JsonPathFilterExpressionType>,
    ) : JsonPathFunctionExtension<JsonPathFilterExpressionValue.NodesTypeValue.FunctionExtensionResult>(
        name = name,
        argumentTypes = argumentTypes,
    )
}

class InvalidFunctionExtensionArgumentsException(
    val functionExtension: JsonPathFunctionExtension<*>,
    val actualArguments: List<JsonPathFilterExpressionValue>
) : Exception(
    "Invalid arguments for function extension \"${functionExtension.name}\": Expected: <${
        functionExtension.argumentTypes.joinToString(", ")
    }>, but received <${actualArguments.map { it.expressionType }.joinToString(", ")}>: <${actualArguments.joinToString(", ")}>"
)