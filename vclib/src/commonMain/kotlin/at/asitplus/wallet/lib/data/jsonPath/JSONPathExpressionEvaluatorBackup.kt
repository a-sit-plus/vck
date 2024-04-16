//package at.asitplus.wallet.lib.data.jsonPath
//
//import at.asitplus.parser.generated.JSONPathBaseVisitor
//import at.asitplus.parser.generated.JSONPathParser
//import kotlinx.serialization.json.JsonElement
//import kotlinx.serialization.json.JsonNull
//import kotlinx.serialization.json.JsonPrimitive
//
//internal class JSONPathExpressionEvaluatorBackup(
//    val rootNode: JsonElement,
//    val currentNode: JsonElement,
//    val functionExtensionManager: JSONPathFunctionExtensionManager,
//) : JSONPathBaseVisitor<JSONPathFunctionExpressionValue>() {
//    override fun visitLogical_expr(ctx: JSONPathParser.Logical_exprContext): JSONPathFunctionExpressionValue {
//        val logicalExpressionEvaluator = JSONPathLogicalExpressionEvaluator(
//            rootNode = rootNode,
//            currentNode = currentNode,
//            functionExtensionManager = functionExtensionManager,
//        )
//        return JSONPathFunctionExpressionValue.LogicalTypeValue(
//            logicalExpressionEvaluator.visitLogical_expr(ctx)
//        )
//    }
//
//    override fun visitRel_query(ctx: JSONPathParser.Rel_queryContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.NodesTypeValue(
//            currentNode.matchJsonPath("$${ctx.segments().text}").map {
//                it.value
//            }
//        )
//    }
//
//    override fun visitJsonpath_query(ctx: JSONPathParser.Jsonpath_queryContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.NodesTypeValue(
//            rootNode.matchJsonPath(ctx.text).map {
//                it.value
//            }
//        )
//    }
//
//    override fun visitFunction_expr(ctx: JSONPathParser.Function_exprContext): JSONPathFunctionExpressionValue {
//        val functionName = ctx.function_name().text
//        val extension = functionExtensionManager.getExtension(functionName)
//            ?: throw UnknownFunctionExtensionException(functionName)
//
//        val suppliedArguments = extension.argumentTypes.zip(ctx.function_argument())
//        val coercedArguments = suppliedArguments.map {
//            val expectedArgumentType = it.first
//            val argumentContext = it.second
//            val argument = visitFunction_argument(argumentContext)
//
//            when (expectedArgumentType) {
//                is JSONPathFunctionExpressionType.LogicalType -> when (argument) {
//                    is JSONPathFunctionExpressionValue.LogicalTypeValue -> argument
//                    is JSONPathFunctionExpressionValue.NodesTypeValue -> JSONPathFunctionExpressionValue.LogicalTypeValue(
//                        argument.nodeList.isNotEmpty()
//                    )
//
//                    is JSONPathFunctionExpressionValue.ValueTypeValue -> throw InvalidArgumentTypeException(
//                        value = argument,
//                        expectedArgumentType = expectedArgumentType,
//                    )
//                }
//
//                is JSONPathFunctionExpressionType.NodesType -> when (argument) {
//                    is JSONPathFunctionExpressionValue.NodesTypeValue -> argument
//                    else -> throw InvalidArgumentTypeException(
//                        value = argument,
//                        expectedArgumentType = expectedArgumentType,
//                    )
//                }
//
//                JSONPathFunctionExpressionType.ValueType -> when (argument) {
//                    is JSONPathFunctionExpressionValue.ValueTypeValue -> argument
//                    is JSONPathFunctionExpressionValue.NodesTypeValue -> {
//                        // this must be a singular query if the static type checker has been invoked
//                        if (argument.nodeList.size == 1) {
//                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(argument.nodeList[0])
//                        } else {
//                            JSONPathFunctionExpressionValue.ValueTypeValue.Nothing
//                        }
//                    }
//
//                    else -> throw InvalidArgumentTypeException(
//                        value = argument,
//                        expectedArgumentType = expectedArgumentType,
//                    )
//                }
//            }
//        }
//        return extension.invoke(coercedArguments)
//    }
//
//    override fun visitRel_singular_query(ctx: JSONPathParser.Rel_singular_queryContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.NodesTypeValue(
//            currentNode.matchJsonPath("$" + ctx.singular_query_segments().text).map { it.value }
//        )
//    }
//
//    override fun visitNumber(ctx: JSONPathParser.NumberContext): JSONPathFunctionExpressionValue {
//        // TODO: support other number formats like long
//        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(
//            JsonPrimitive(ctx.text.toDouble())
//        )
//    }
//
//    override fun visitString_literal(ctx: JSONPathParser.String_literalContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(
//            JsonPrimitive(ctx.toUnescapedString())
//        )
//    }
//
//    override fun visitNull(ctx: JSONPathParser.NullContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonNull)
//    }
//
//    override fun visitTrue(ctx: JSONPathParser.TrueContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(true))
//    }
//
//    override fun visitFalse(ctx: JSONPathParser.FalseContext): JSONPathFunctionExpressionValue {
//        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(false))
//    }
//}