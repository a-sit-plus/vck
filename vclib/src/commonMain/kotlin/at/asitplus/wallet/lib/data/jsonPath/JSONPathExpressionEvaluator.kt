package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathParser
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull

internal class JSONPathExpressionEvaluator(
    val rootNode: JsonElement,
    val currentNode: JsonElement,
    val functionExtensionManager: JSONPathFunctionExtensionManager,
) : JSONPathBaseVisitor<JSONPathFunctionExpressionValue>() {

    override fun visitLogical_expr(ctx: JSONPathParser.Logical_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        return visitLogical_or_expr(ctx.logical_or_expr())
    }

    override fun visitLogical_or_expr(ctx: JSONPathParser.Logical_or_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        return JSONPathFunctionExpressionValue.LogicalTypeValue(ctx.logical_and_expr().any {
            visitLogical_and_expr(it).isTrue
        })
    }

    override fun visitLogical_and_expr(ctx: JSONPathParser.Logical_and_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        return JSONPathFunctionExpressionValue.LogicalTypeValue(ctx.basic_expr().all {
            visitBasic_expr(it).isTrue
        })
    }

    override fun visitBasic_expr(ctx: JSONPathParser.Basic_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        return ctx.comparison_expr()?.let {
            visitComparison_expr(it)
        } ?: ctx.test_expr()?.let {
            visitTest_expr(it)
        } ?: ctx.paren_expr()?.let {
            visitParen_expr(it)
        } ?: throw UnexpectedTokenException(ctx)
    }

    override fun visitParen_expr(ctx: JSONPathParser.Paren_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val evaluation = visitLogical_expr(ctx.logical_expr())
        return JSONPathFunctionExpressionValue.LogicalTypeValue(
            if (negate) {
                !evaluation.isTrue
            } else {
                evaluation.isTrue
            }
        )
    }

    override fun visitComparison_expr(ctx: JSONPathParser.Comparison_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        // see section 2.3.5.2.2
        val firstComparable = ctx.comparable(0) ?: throw UnexpectedTokenException(ctx)
        val secondComparable = ctx.comparable(1) ?: throw UnexpectedTokenException(ctx)

        val comparisonResult = ctx.comparisonOp().let {
            when {
                it.equalsOp() != null -> this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.smallerThanOp() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable,
                )

                it.notEqualsOp() != null -> !this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.smallerThanOrEqualsOp() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable,
                ) or this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                it.greaterThanOp() != null -> evaluateComparisonSmallerThan(
                    secondComparable,
                    firstComparable,
                )

                it.greaterThanOrEqualsOp() != null -> evaluateComparisonSmallerThan(
                    secondComparable,
                    firstComparable,
                ) or this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable,
                )

                else -> throw UnexpectedTokenException(ctx.comparisonOp())
            }
        }

        return JSONPathFunctionExpressionValue.LogicalTypeValue(comparisonResult)
    }

    internal fun evaluateComparisonEquals(
        first: JSONPathParser.ComparableContext,
        second: JSONPathParser.ComparableContext,
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
        first: JSONPathFunctionExpressionValue.ValueTypeValue,
        second: JSONPathFunctionExpressionValue.ValueTypeValue,
    ): Boolean = when (first) {
        is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue -> when (first.jsonElement) {
            is JsonArray -> if (second is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
                if (second.jsonElement is JsonArray) {
                    (first.jsonElement.size == second.jsonElement.size) and first.jsonElement.mapIndexed { index, it ->
                        index to it
                    }.all {
                        this.evaluateComparisonEqualsUnpacked(
                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(it.second),
                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(second.jsonElement[it.first]),
                        )
                    }
                } else false
            } else false

            is JsonObject -> if (second is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
                if (second.jsonElement is JsonObject) {
                    (first.jsonElement.keys == second.jsonElement.keys) and first.jsonElement.entries.all {
                        this.evaluateComparisonEqualsUnpacked(
                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(it.value),
                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(
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

            is JsonPrimitive -> if (second is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
                if (second.jsonElement is JsonPrimitive) {
                    first.jsonElement.booleanOrNull?.let { it == second.jsonElement.booleanOrNull }
                        ?: first.jsonElement.longOrNull?.let { it == second.jsonElement.longOrNull }
                        ?: first.jsonElement.doubleOrNull?.let { it == second.jsonElement.doubleOrNull }
                        ?: first.jsonElement.contentOrNull?.let { it == second.jsonElement.contentOrNull }
                        ?: false
                } else false
            } else false

            JsonNull -> if (second is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
                second.jsonElement == JsonNull
            } else false
        }

        JSONPathFunctionExpressionValue.ValueTypeValue.Nothing -> second == JSONPathFunctionExpressionValue.ValueTypeValue.Nothing
    }

    internal fun evaluateComparisonSmallerThan(
        first: JSONPathParser.ComparableContext,
        second: JSONPathParser.ComparableContext,
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
        first: JSONPathFunctionExpressionValue,
        second: JSONPathFunctionExpressionValue,
    ): Boolean {
        if (first !is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
            return false
        }
        if (second !is JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue) {
            return false
        }
        if (first.jsonElement !is JsonPrimitive) {
            return false
        }
        if (second.jsonElement !is JsonPrimitive) {
            return false
        }
        return first.jsonElement.booleanOrNull?.let { false }
            ?: first.jsonElement.longOrNull?.let {
                second.jsonElement.longOrNull?.let { other -> it < other } ?: false
            }
            ?: first.jsonElement.doubleOrNull?.let {
                second.jsonElement.doubleOrNull?.let { other -> it < other } ?: false
            }
            ?: first.jsonElement.contentOrNull?.let {
                second.jsonElement.contentOrNull?.let { other ->
                    it < other
                }
            }
            ?: false
    }

    override fun visitTest_expr(ctx: JSONPathParser.Test_exprContext): JSONPathFunctionExpressionValue.LogicalTypeValue {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val result = when (val it = visitChildren(ctx)) {
            is JSONPathFunctionExpressionValue.LogicalTypeValue -> it.isTrue
            is JSONPathFunctionExpressionValue.NodesTypeValue -> it.nodeList.isNotEmpty()
            else -> throw InvalidTestExpressionValueException(expression = ctx, value = it)
        }

        return JSONPathFunctionExpressionValue.LogicalTypeValue(
            if (negate) {
                !result
            } else {
                result
            }
        )
    }

    override fun visitRel_query(ctx: JSONPathParser.Rel_queryContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.NodesTypeValue(
            currentNode.matchJsonPath("$${ctx.segments().text}").map {
                it.value
            }
        )
    }

    override fun visitJsonpath_query(ctx: JSONPathParser.Jsonpath_queryContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.NodesTypeValue(
            rootNode.matchJsonPath(ctx.text).map {
                it.value
            }
        )
    }

    override fun visitFunction_expr(ctx: JSONPathParser.Function_exprContext): JSONPathFunctionExpressionValue {
        val functionName = ctx.function_name().text
        val extension = functionExtensionManager.getExtension(functionName)
            ?: throw UnknownFunctionExtensionException(functionName)

        val suppliedArguments = extension.argumentTypes.zip(ctx.function_argument())
        val coercedArguments = suppliedArguments.map {
            val expectedArgumentType = it.first
            val argumentContext = it.second
            val argument = visitFunction_argument(argumentContext)

            when (expectedArgumentType) {
                is JSONPathFunctionExpressionType.LogicalType -> when (argument) {
                    is JSONPathFunctionExpressionValue.LogicalTypeValue -> argument
                    is JSONPathFunctionExpressionValue.NodesTypeValue -> JSONPathFunctionExpressionValue.LogicalTypeValue(
                        argument.nodeList.isNotEmpty()
                    )

                    is JSONPathFunctionExpressionValue.ValueTypeValue -> throw InvalidArgumentTypeException(
                        value = argument,
                        expectedArgumentType = expectedArgumentType,
                    )
                }

                is JSONPathFunctionExpressionType.NodesType -> when (argument) {
                    is JSONPathFunctionExpressionValue.NodesTypeValue -> argument
                    else -> throw InvalidArgumentTypeException(
                        value = argument,
                        expectedArgumentType = expectedArgumentType,
                    )
                }

                JSONPathFunctionExpressionType.ValueType -> when (argument) {
                    is JSONPathFunctionExpressionValue.ValueTypeValue -> argument
                    is JSONPathFunctionExpressionValue.NodesTypeValue -> {
                        // this must be a singular query if the static type checker has been invoked
                        if (argument.nodeList.size == 1) {
                            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(argument.nodeList[0])
                        } else {
                            JSONPathFunctionExpressionValue.ValueTypeValue.Nothing
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

    override fun visitRel_singular_query(ctx: JSONPathParser.Rel_singular_queryContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.NodesTypeValue(
            currentNode.matchJsonPath("$" + ctx.singular_query_segments().text).map { it.value }
        )
    }

    override fun visitNumber(ctx: JSONPathParser.NumberContext): JSONPathFunctionExpressionValue {
        // TODO: support other number formats like long
        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(ctx.text.toDouble())
        )
    }

    override fun visitString_literal(ctx: JSONPathParser.String_literalContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(
            JsonPrimitive(ctx.toUnescapedString())
        )
    }

    override fun visitNull(ctx: JSONPathParser.NullContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonNull)
    }

    override fun visitTrue(ctx: JSONPathParser.TrueContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(true))
    }

    override fun visitFalse(ctx: JSONPathParser.FalseContext): JSONPathFunctionExpressionValue {
        return JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(JsonPrimitive(false))
    }
}


private fun JSONPathFunctionExpressionValue.isEmptyOrNothing(): Boolean = when (this) {
    is JSONPathFunctionExpressionValue.NodesTypeValue -> this.nodeList.isEmpty()
    JSONPathFunctionExpressionValue.ValueTypeValue.Nothing -> true
    else -> false
}

// When any query or function expression on either side of a comparison
// results in a nodelist consisting of a single node, that side is
// replaced by the value of its node.
// source: https://datatracker.ietf.org/doc/rfc9535/
private fun JSONPathFunctionExpressionValue.toComparisonValue(): JSONPathFunctionExpressionValue.ValueTypeValue? =
    when (this) {
        is JSONPathFunctionExpressionValue.ValueTypeValue -> this
        is JSONPathFunctionExpressionValue.NodesTypeValue -> if (this.nodeList.size == 1) {
            JSONPathFunctionExpressionValue.ValueTypeValue.JsonValue(this.nodeList[0])
        } else if (this.nodeList.size > 1) {
            null // invalid intermediate value
        } else {
            JSONPathFunctionExpressionValue.ValueTypeValue.Nothing
        }

        is JSONPathFunctionExpressionValue.LogicalTypeValue -> null
    }