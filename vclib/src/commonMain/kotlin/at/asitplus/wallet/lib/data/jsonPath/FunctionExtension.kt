package at.asitplus.wallet.lib.data.jsonPath

import com.strumenta.antlrkotlin.runtime.assert
import com.strumenta.antlrkotlin.runtime.ext.codePointIndices

class InvalidArgumentsException(val expectedArguments: Int, val actualArguments: Int) : Exception(
    "Invalid number of arguments. Expected $expectedArguments, but received $actualArguments."
)
class InvalidArgumentTypeException(val value: JSONPathFilterExpressionValue, val expectedArgument: JSONPathFilterExpressionValue) : Exception(
    "Unexpected argument type: $value"
)

sealed class FunctionExtension(
    val name: String,
    val evaluator: FunctionExtensionEvaluator,
)

abstract class FunctionExtensionEvaluator(
    val expectedArguments: Int,
) {
    abstract fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue

    fun validateArgumentList(arguments: List<JSONPathFilterExpressionValue>) {
        if (arguments.size != this.expectedArguments) {
            throw InvalidArgumentsException(
                expectedArguments = expectedArguments,
                actualArguments = arguments.size
            )
        }
    }
}

data object LengthFunctionExtension : FunctionExtension(
    name = "length",
    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 1) {
        override fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue {
            super.validateArgumentList(arguments)
            val argument = arguments[0].deduplicate()
            assert(argument != JSONPathFilterExpressionValue.Nothing)
            assert(argument !is JSONPathFilterExpressionValue.LogicalValue)
            assert(argument !is JSONPathFilterExpressionValue.NodeListValue)
            return when (argument) {
                is JSONPathFilterExpressionValue.StringValue -> JSONPathFilterExpressionValue.NumberValue.UIntValue(
                    argument.string.codePointIndices().size.toUInt()
                )

                is JSONPathFilterExpressionValue.JsonArrayValue -> JSONPathFilterExpressionValue.NumberValue.UIntValue(
                    argument.jsonArray.size.toUInt()
                )

                is JSONPathFilterExpressionValue.JsonObjectValue -> JSONPathFilterExpressionValue.NumberValue.UIntValue(
                    argument.jsonObject.size.toUInt()
                )

                else -> JSONPathFilterExpressionValue.Nothing
            }
        }
    },
)

data object CountFunctionExtension : FunctionExtension(
    name = "count",
    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 1) {
        override fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue {
            super.validateArgumentList(arguments)
            val argument = arguments[0]
            assert(argument is JSONPathFilterExpressionValue.NodeListValue)
            return JSONPathFilterExpressionValue.NumberValue.UIntValue(
                argument.nodeList.size.toUInt()
            )
        }
    },
)

data object MatchFunctionExtension : FunctionExtension(
    name = "match",
    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
        override fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue {
            super.validateArgumentList(arguments)
            val argument1 = arguments[0].deduplicate()
            val argument2 = arguments[1].deduplicate()
            assert(argument1 is JSONPathFilterExpressionValue.StringValue)
            assert(argument2 is JSONPathFilterExpressionValue.StringValue)
            return JSONPathFilterExpressionValue.LogicalValue(
                Regex(argument2.string).matches(argument1.string)
            )
        }
    },
)

data object SearchFunctionExtension : FunctionExtension(
    name = "search",
    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
        override fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue {
            super.validateArgumentList(arguments)
            val argument1 = arguments[0].deduplicate()
            val argument2 = arguments[1].deduplicate()
            assert(argument1 is JSONPathFilterExpressionValue.StringValue)
            assert(argument2 is JSONPathFilterExpressionValue.StringValue)
            return JSONPathFilterExpressionValue.LogicalValue(
                Regex(argument2.string).containsMatchIn(argument1.string)
            )
        }
    },
)

data object ValueFunctionExtension : FunctionExtension(
    name = "value",
    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
        override fun invoke(arguments: List<JSONPathFilterExpressionValue>): JSONPathFilterExpressionValue {
            super.validateArgumentList(arguments)
            val argument = arguments[0].deduplicate()
            return when(argument) {
                is JSONPathFilterExpressionValue.NodeListValue -> JSONPathFilterExpressionValue.Nothing
                else -> argument
            }
        }
    },
)

private fun JSONPathFilterExpressionValue.deduplicate(): JSONPathFilterExpressionValue {
    return if(this !is JSONPathFilterExpressionValue.NodeListValue) {
        this
    } else if (this.nodeList.size == 1) {
        this.nodeList[0].toJSONPathFilterExpressionValue()
    } else {
        this
    }
}

private fun <T : JSONPathFilterExpressionValue> JSONPathFilterExpressionValue.coerceTo(): JSONPathFilterExpressionValue {
    return if(this !is JSONPathFilterExpressionValue.NodeListValue) {
        this
    } else if (this.nodeList.size == 1) {
        this.nodeList[0].toJSONPathFilterExpressionValue()
    } else {
        this
    }
}