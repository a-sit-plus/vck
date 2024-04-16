package at.asitplus.wallet.lib.data.jsonPath

import io.ktor.http.quote

sealed class JSONPathFunctionExtension<ReturnType : JSONPathFunctionExpressionValue>(
    val name: String,
    val argumentTypes: List<JSONPathFunctionExpressionType>,
) {
    abstract fun invoke(arguments: List<JSONPathFunctionExpressionValue>): ReturnType
    abstract class ValueTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathFunctionExpressionType>,
    ) : JSONPathFunctionExtension<JSONPathFunctionExpressionValue.ValueTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class LogicalTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathFunctionExpressionType>,
    ) : JSONPathFunctionExtension<JSONPathFunctionExpressionValue.LogicalTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )

    abstract class NodesTypeFunctionExtension(
        name: String,
        argumentTypes: List<JSONPathFunctionExpressionType>,
    ) : JSONPathFunctionExtension<JSONPathFunctionExpressionValue.NodesTypeValue>(
        name = name,
        argumentTypes = argumentTypes,
    )
}


//data object LengthFunctionExtension : FunctionExtension.ValueTypeFunctionExtension(
//    name = "length",
//    argumentTypes = listOf(
//        JSONPathFunctionExpressionType.ValueType
//    )
//) {
//    override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathFunctionExpressionValue.ValueTypeValue {
//
//        val argument = arguments[0].deduplicate()
//        assert(argument != JSONPathExpressionValue.Nothing)
//        assert(argument !is JSONPathExpressionValue.LogicalValue)
//        assert(argument !is JSONPathExpressionValue.NodeListValue)
//        return when (argument) {
//            is JSONPathExpressionValue.StringValue -> JSONPathExpressionValue.NumberValue.UIntValue(
//                argument.string.codePointIndices().size.toUInt()
//            )
//
//            is JSONPathExpressionValue.JsonArrayValue -> JSONPathExpressionValue.NumberValue.UIntValue(
//                argument.jsonArray.size.toUInt()
//            )
//
//            is JSONPathExpressionValue.JsonObjectValue -> JSONPathExpressionValue.NumberValue.UIntValue(
//                argument.jsonObject.size.toUInt()
//            )
//
//            else -> JSONPathExpressionValue.Nothing
//        }
//    }
//}

//data object CountFunctionExtension : FunctionExtension(
//    name = "count",
//    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 1) {
//        override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue {
//            super.validateArgumentList(arguments)
//            val argument = arguments[0]
//            assert(argument is JSONPathExpressionValue.NodeListValue)
//            return JSONPathExpressionValue.NumberValue.UIntValue(
//                argument.nodeList.size.toUInt()
//            )
//        }
//    },
//)
//
//data object MatchFunctionExtension : FunctionExtension(
//    name = "match",
//    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
//        override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue {
//            super.validateArgumentList(arguments)
//            val argument1 = arguments[0].deduplicate()
//            val argument2 = arguments[1].deduplicate()
//            assert(argument1 is JSONPathExpressionValue.StringValue)
//            assert(argument2 is JSONPathExpressionValue.StringValue)
//            return JSONPathExpressionValue.LogicalValue(
//                Regex(argument2.string).matches(argument1.string)
//            )
//        }
//    },
//)
//
//data object SearchFunctionExtension : FunctionExtension(
//    name = "search",
//    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
//        override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue {
//            super.validateArgumentList(arguments)
//            val argument1 = arguments[0].deduplicate()
//            val argument2 = arguments[1].deduplicate()
//            assert(argument1 is JSONPathExpressionValue.StringValue)
//            assert(argument2 is JSONPathExpressionValue.StringValue)
//            return JSONPathExpressionValue.LogicalValue(
//                Regex(argument2.string).containsMatchIn(argument1.string)
//            )
//        }
//    },
//)
//
//data object ValueFunctionExtension : FunctionExtension(
//    name = "value",
//    evaluator = object : FunctionExtensionEvaluator(expectedArguments = 2) {
//        override fun invoke(arguments: List<JSONPathExpressionValue>): JSONPathExpressionValue {
//            super.validateArgumentList(arguments)
//            val argument = arguments[0].deduplicate()
//            return when(argument) {
//                is JSONPathExpressionValue.NodeListValue -> JSONPathExpressionValue.Nothing
//                else -> argument
//            }
//        }
//    },
//)

private fun JSONPathExpressionValue.deduplicate(): JSONPathExpressionValue {
    return if(this !is JSONPathExpressionValue.NodeListValue) {
        this
    } else if (this.nodeList.size == 1) {
        this.nodeList[0].toJSONPathFilterExpressionValue()
    } else {
        this
    }
}

class InvalidArgumentsException(val expectedArguments: Int, val actualArguments: Int) : Exception(
    "Invalid number of arguments. Expected $expectedArguments, but received $actualArguments."
)
class InvalidArgumentTypeException(val value: JSONPathFunctionExpressionValue, val expectedArgumentType: JSONPathFunctionExpressionType) : Exception(
    "Unexpected argument type: Expected value of type ${expectedArgumentType.toString().quote()}, received: $value"
)