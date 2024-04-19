package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

internal class JsonPathExpressionEvaluationVisitor(
    val rootNode: JsonElement,
    val currentNode: JsonElement,
    val compiler: JsonPathCompiler,
) : JsonPathParserBaseVisitor<JsonPathExpressionValue>() {

    override fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        return visitLogical_or_expr(ctx.logical_or_expr())
    }

    override fun visitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        return JsonPathExpressionValue.LogicalTypeValue(ctx.logical_and_expr().any {
            visitLogical_and_expr(it).isTrue
        })
    }

    override fun visitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        return JsonPathExpressionValue.LogicalTypeValue(ctx.basic_expr().all {
            visitBasic_expr(it).isTrue
        })
    }

    override fun visitBasic_expr(ctx: JsonPathParser.Basic_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        return ctx.comparison_expr()?.let {
            visitComparison_expr(it)
        } ?: ctx.test_expr()?.let {
            visitTest_expr(it)
        } ?: ctx.paren_expr()?.let {
            visitParen_expr(it)
        } ?: throw UnexpectedTokenException(ctx)
    }

    override fun visitParen_expr(ctx: JsonPathParser.Paren_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val evaluation = visitLogical_expr(ctx.logical_expr())
        return JsonPathExpressionValue.LogicalTypeValue(
            if (negate) {
                !evaluation.isTrue
            } else {
                evaluation.isTrue
            }
        )
    }

    override fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        // see section 2.3.5.2.2
        val firstComparable = ctx.comparable(0) ?: throw UnexpectedTokenException(ctx)
        val secondComparable = ctx.comparable(1) ?: throw UnexpectedTokenException(ctx)

        val comparisonResult = ctx.comparisonOp().let {
            when {
                it.COMPARISON_OP_EQUALS() != null -> this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.COMPARISON_OP_SMALLER_THAN() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable,
                )

                it.COMPARISON_OP_NOT_EQUALS() != null -> !this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.COMPARISON_OP_SMALLER_THAN_OR_EQUALS() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable,
                ) or this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.COMPARISON_OP_GREATER_THAN() != null -> evaluateComparisonSmallerThan(
                    secondComparable,
                    firstComparable,
                )

                it.COMPARISON_OP_GREATER_THAN_OR_EQUALS() != null -> evaluateComparisonSmallerThan(
                    secondComparable,
                    firstComparable,
                ) or this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                else -> throw UnexpectedTokenException(ctx.comparisonOp())
            }
        }

        return JsonPathExpressionValue.LogicalTypeValue(comparisonResult)
    }

    internal fun evaluateComparisonEquals(
        first: JsonPathParser.ComparableContext,
        second: JsonPathParser.ComparableContext,
    ): Boolean {
        val firstValue = visitComparable(first)
        val secondValue = visitComparable(second)

        if (firstValue.isEmptyOrNothing() or secondValue.isEmptyOrNothing()) {
            return firstValue.isEmptyOrNothing() != secondValue.isEmptyOrNothing()
        }

        return evaluateComparisonEqualsUnpacked(
            firstValue.toComparisonValue() ?: throw InvalidComparableValueException(
                expression = first,
                value = firstValue,
            ),
            secondValue.toComparisonValue() ?: throw InvalidComparableValueException(
                expression = second,
                value = secondValue,
            ),
        )
    }

    internal fun evaluateComparisonEqualsUnpacked(
        first: JsonPathExpressionValue.ValueTypeValue,
        second: JsonPathExpressionValue.ValueTypeValue,
    ): Boolean = when (first) {
        is JsonPathExpressionValue.ValueTypeValue.JsonValue -> {
            when (first.jsonElement) {
                is JsonArray -> if (second is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
                    if (second.jsonElement is JsonArray) {
                        (first.jsonElement.size == second.jsonElement.size) and first.jsonElement.mapIndexed { index, it ->
                            index to it
                        }.all {
                            this.evaluateComparisonEqualsUnpacked(
                                JsonPathExpressionValue.ValueTypeValue.JsonValue(it.second),
                                JsonPathExpressionValue.ValueTypeValue.JsonValue(second.jsonElement[it.first]),
                            )
                        }
                    } else false
                } else false

                is JsonObject -> if (second is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
                    if (second.jsonElement is JsonObject) {
                        (first.jsonElement.keys == second.jsonElement.keys) and first.jsonElement.entries.all {
                            this.evaluateComparisonEqualsUnpacked(
                                JsonPathExpressionValue.ValueTypeValue.JsonValue(it.value),
                                JsonPathExpressionValue.ValueTypeValue.JsonValue(
                                    second.jsonElement[it.key]
                                        ?: throw MissingKeyException(
                                            jsonObject = second.jsonElement,
                                            key = it.key
                                        )
                                )
                            )
                        }
                    } else false
                } else false

                is JsonPrimitive -> if (second is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
                    if (second.jsonElement is JsonPrimitive) {
                        when {
                            first.jsonElement.isString != second.jsonElement.isString -> false
                            first.jsonElement.isString -> first.jsonElement.content == second.jsonElement.content
                            else -> first.jsonElement.booleanOrNull?.let { it == second.jsonElement.booleanOrNull }
                                ?: first.jsonElement.longOrNull?.let { it == second.jsonElement.longOrNull }
                                ?: first.jsonElement.doubleOrNull?.let { it == second.jsonElement.doubleOrNull }
                                ?: false
                        }
                    } else false
                } else false

                JsonNull -> if (second is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
                    second.jsonElement == JsonNull
                } else false
            }
        }

        JsonPathExpressionValue.ValueTypeValue.Nothing -> second == JsonPathExpressionValue.ValueTypeValue.Nothing
    }

    internal fun evaluateComparisonSmallerThan(
        first: JsonPathParser.ComparableContext,
        second: JsonPathParser.ComparableContext,
    ): Boolean {
        val firstValue = visitComparable(first)
        val secondValue = visitComparable(second)

        if (firstValue.isEmptyOrNothing() or secondValue.isEmptyOrNothing()) return false

        return evaluateComparisonUnpackedSmallerThan(
            firstValue.toComparisonValue() ?: throw InvalidComparableValueException(
                expression = first,
                value = firstValue,
            ),
            secondValue.toComparisonValue() ?: throw InvalidComparableValueException(
                expression = second,
                value = secondValue,
            ),
        )
    }

    internal fun evaluateComparisonUnpackedSmallerThan(
        first: JsonPathExpressionValue,
        second: JsonPathExpressionValue,
    ): Boolean {
        if (first !is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
            return false
        }
        if (second !is JsonPathExpressionValue.ValueTypeValue.JsonValue) {
            return false
        }
        if (first.jsonElement !is JsonPrimitive) {
            return false
        }
        if (second.jsonElement !is JsonPrimitive) {
            return false
        }
        if (first.jsonElement.isString != second.jsonElement.isString) {
            return false
        }
        if (first.jsonElement.isString) {
            return first.jsonElement.content < second.jsonElement.content
        }
        return first.jsonElement.longOrNull?.let { firstValue ->
            second.jsonElement.longOrNull?.let { firstValue < it }
                ?: second.jsonElement.doubleOrNull?.let { firstValue < it }
        } ?: first.jsonElement.doubleOrNull?.let { firstValue ->
            second.jsonElement.longOrNull?.let { firstValue < it }
                ?: second.jsonElement.doubleOrNull?.let { firstValue < it }
        } ?: false
    }

    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): JsonPathExpressionValue.LogicalTypeValue {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val result = when (val it = visitChildren(ctx)) {
            is JsonPathExpressionValue.LogicalTypeValue -> it.isTrue
            is JsonPathExpressionValue.NodesTypeValue -> it.nodeList.isNotEmpty()
            else -> throw InvalidTestExpressionValueException(expression = ctx, value = it)
        }

        return JsonPathExpressionValue.LogicalTypeValue(
            if (negate) {
                !result
            } else {
                result
            }
        )
    }

    override fun visitRel_query(ctx: JsonPathParser.Rel_queryContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.NodesTypeValue.FilterQueryResult(
            compiler.compile("$${ctx.segments().text}").invoke(currentNode).map {
                it.value
            }
        )
    }

    override fun visitJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.NodesTypeValue.FilterQueryResult(
            compiler.compile(ctx.text).invoke(rootNode).map {
                it.value
            }
        )
    }

    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): JsonPathExpressionValue {
        val functionName = ctx.FUNCTION_NAME().text
        val extension = compiler.getFunctionExtensionManager()?.getExtension(functionName)
            ?: throw UnknownFunctionExtensionException(functionName)

        if(ctx.function_argument().size != extension.argumentTypes.size) {
            throw InvalidArgumentsException(
                expectedArguments = extension.argumentTypes.size,
                actualArguments = ctx.function_argument().size,
            )
        }
        val coercedArguments = extension.argumentTypes.zip(ctx.function_argument()).map {
            val expectedArgumentType = it.first
            val argumentContext = it.second
            val argument = visitFunction_argument(argumentContext)

            when (expectedArgumentType) {
                JsonPathExpressionTypeEnum.LogicalType -> when (argument) {
                    is JsonPathExpressionValue.LogicalTypeValue -> argument
                    is JsonPathExpressionValue.NodesTypeValue -> JsonPathExpressionValue.LogicalTypeValue(
                        argument.nodeList.isNotEmpty()
                    )

                    is JsonPathExpressionValue.ValueTypeValue -> throw InvalidArgumentTypeException(
                        value = argument,
                        expectedArgumentType = expectedArgumentType,
                    )
                }

                JsonPathExpressionTypeEnum.NodesType -> when (argument) {
                    is JsonPathExpressionValue.NodesTypeValue -> argument
                    else -> throw InvalidArgumentTypeException(
                        value = argument,
                        expectedArgumentType = expectedArgumentType,
                    )
                }

                JsonPathExpressionTypeEnum.ValueType -> when (argument) {
                    is JsonPathExpressionValue.ValueTypeValue -> argument
                    is JsonPathExpressionValue.NodesTypeValue -> {
                        if (argument !is JsonPathExpressionValue.NodesTypeValue.SingularQueryResult) {
                            throw InvalidArgumentTypeException(
                                value = argument,
                                expectedArgumentType = expectedArgumentType,
                            )
                        } else if(argument.nodeList.size == 1) {
                            JsonPathExpressionValue.ValueTypeValue.JsonValue(argument.nodeList[0])
                        } else {
                            JsonPathExpressionValue.ValueTypeValue.Nothing
                        }
                    }

                    else -> throw InvalidArgumentTypeException(
                        value = argument,
                        expectedArgumentType = expectedArgumentType,
                    )
                }
            }
        }
        return extension.invoke(coercedArguments)
    }

    override fun visitRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.NodesTypeValue.SingularQueryResult(
            compiler.compile("$" + ctx.singular_query_segments().text).invoke(currentNode)
                .map { it.value }
        )
    }

    override fun visitNumber(ctx: JsonPathParser.NumberContext): JsonPathExpressionValue {
        // TODO: support other number formats like long
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(
            // DO NOT CREATE THIS PRIMITIVE FROM THE TEXT
            // - JsonPrimitive.isString is the only way to know whether the content is actually a string
            JsonPrimitive(ctx.text.toDouble())
        )
    }

    override fun visitStringLiteral(ctx: JsonPathParser.StringLiteralContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(ctx.toUnescapedString())
        )
    }

    override fun visitNull(ctx: JsonPathParser.NullContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(JsonNull)
    }

    override fun visitTrue(ctx: JsonPathParser.TrueContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(true))
    }

    override fun visitFalse(ctx: JsonPathParser.FalseContext): JsonPathExpressionValue {
        return JsonPathExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(false))
    }
}


private fun JsonPathExpressionValue.isEmptyOrNothing(): Boolean = when (this) {
    is JsonPathExpressionValue.NodesTypeValue -> this.nodeList.isEmpty()
    JsonPathExpressionValue.ValueTypeValue.Nothing -> true
    else -> false
}

// When any query or function expression on either side of a comparison
// results in a nodelist consisting of a single node, that side is
// replaced by the value of its node.
// source: https://datatracker.ietf.org/doc/rfc9535/
private fun JsonPathExpressionValue.toComparisonValue(): JsonPathExpressionValue.ValueTypeValue? =
    when (this) {
        is JsonPathExpressionValue.ValueTypeValue -> this
        is JsonPathExpressionValue.NodesTypeValue -> if (this.nodeList.size == 1) {
            JsonPathExpressionValue.ValueTypeValue.JsonValue(this.nodeList[0])
        } else if (this.nodeList.size > 1) {
            null // invalid intermediate value
        } else {
            JsonPathExpressionValue.ValueTypeValue.Nothing
        }

        is JsonPathExpressionValue.LogicalTypeValue -> null
    }