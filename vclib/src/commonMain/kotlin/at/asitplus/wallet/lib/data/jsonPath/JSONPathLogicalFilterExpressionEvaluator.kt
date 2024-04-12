package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathParser
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.buildJsonArray

internal class JSONPathLogicalFilterExpressionEvaluator(
    val rootNode: JsonElement,
    val currentNode: JsonElement,
    val functionExtensions: Map<String, FunctionExtensionEvaluator>
) : JSONPathBaseVisitor<Boolean>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21

    override fun visitLogicalOrExpr(ctx: JSONPathParser.LogicalOrExprContext): Boolean {
        return ctx.logicalAndExpr().any {
            visitLogicalAndExpr(it)
        }
    }

    override fun visitLogicalAndExpr(ctx: JSONPathParser.LogicalAndExprContext): Boolean {
        return ctx.basicExpr().all {
            visitBasicExpr(it)
        }
    }

    override fun visitParenExpr(ctx: JSONPathParser.ParenExprContext): Boolean {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val evaluation = visitLogicalExpr(ctx.logicalExpr())
        return if (negate) {
            !evaluation
        } else {
            evaluation
        }
    }

    override fun visitComparisonExpr(ctx: JSONPathParser.ComparisonExprContext): Boolean {
        // see section 2.3.5.2.2
        val expressionEvaluator = JSONPathFilterExpressionEvaluator(
            rootNode = rootNode,
            currentNode = currentNode,
            functionExtensions = functionExtensions,
        )
        val firstComparable =
            expressionEvaluator.visitComparable(
                ctx.comparable(0) ?: throw UnexpectedTokenException(
                    ctx
                )
            )
        val secondComparable =
            expressionEvaluator.visitComparable(
                ctx.comparable(1) ?: throw UnexpectedTokenException(
                    ctx
                )
            )
        val comparisonResult = ctx.comparisonOp().let {
            when {
                it.equalsOp() != null -> this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable
                )

                it.notEqualsOp() != null -> !this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable
                )

                it.smallerOrEqualsOp() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable
                ) or this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable
                )

                it.greaterOrEqualsOp() != null -> !evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable
                )

                it.smallerThanOp() != null -> evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable
                )

                it.greaterThanOp() != null -> !evaluateComparisonSmallerThan(
                    firstComparable,
                    secondComparable
                ) and !this.evaluateComparisonEquals(
                    firstComparable,
                    secondComparable
                )

                else -> throw UnexpectedTokenException(ctx.comparisonOp())
            }
        }

        return comparisonResult
    }

    internal fun evaluateComparisonEquals(
        first: JSONPathFilterExpressionValue,
        second: JSONPathFilterExpressionValue,
    ): Boolean {
        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) return false

        return evaluateComparisonEqualsUnpacked(
            first.toComparisonValue(),
            second.toComparisonValue(),
        )
    }

    internal fun evaluateComparisonEqualsUnpacked(
        first: JSONPathFilterExpressionValue,
        second: JSONPathFilterExpressionValue,
    ): Boolean = when (first) {
        is JSONPathFilterExpressionValue.NumberValue -> if (second is JSONPathFilterExpressionValue.NumberValue) {
            first == second
        } else false

        is JSONPathFilterExpressionValue.StringValue -> if (second is JSONPathFilterExpressionValue.StringValue) {
            first.string == second.string
        } else false

        is JSONPathFilterExpressionValue.LogicalValue -> if (second is JSONPathFilterExpressionValue.LogicalValue) {
            first.isTrue == second.isTrue
        } else false

        is JSONPathFilterExpressionValue.JsonObjectValue -> if (second is JSONPathFilterExpressionValue.JsonObjectValue) {
            (first.jsonObject.keys == second.jsonObject.keys) and first.jsonObject.entries.all {
                this.evaluateComparisonEqualsUnpacked(
                    it.value.toJSONPathFilterExpressionValue(),
                    second.jsonObject[it.key]?.toJSONPathFilterExpressionValue()
                        ?: throw MissingKeyException(
                            jsonObject = second.jsonObject,
                            key = it.key
                        ),
                )
            }
        } else false

        is JSONPathFilterExpressionValue.JsonArrayValue -> if (second is JSONPathFilterExpressionValue.JsonArrayValue) {
            (first.jsonArray.size == second.jsonArray.size) and first.jsonArray.mapIndexed { index, it ->
                index to it
            }.all {
                this.evaluateComparisonEqualsUnpacked(
                    it.second.toJSONPathFilterExpressionValue(),
                    second.jsonArray[it.first].toJSONPathFilterExpressionValue(),
                )
            }
        } else false

        is JSONPathFilterExpressionValue.NodeListValue -> if (first.nodeList.isEmpty()) {
            second.isEmptyOrNothing()
        } else if (second is JSONPathFilterExpressionValue.NodeListValue) {
            this.evaluateComparisonEqualsUnpacked(
                JSONPathFilterExpressionValue.JsonArrayValue(buildJsonArray {
                    first.nodeList.forEach { add(it) }
                }),
                JSONPathFilterExpressionValue.JsonArrayValue(buildJsonArray {
                    second.nodeList.forEach { add(it) }
                }),
            )
        } else false

        JSONPathFilterExpressionValue.NullValue -> second is JSONPathFilterExpressionValue.NullValue
        JSONPathFilterExpressionValue.Nothing -> second.isEmptyOrNothing()
    }

    internal fun evaluateComparisonSmallerThan(
        first: JSONPathFilterExpressionValue,
        second: JSONPathFilterExpressionValue,
    ): Boolean {
        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) return false

        return evaluateComparisonUnpackedSmallerThan(
            first.toComparisonValue(),
            second.toComparisonValue(),
        )
    }

    internal fun evaluateComparisonUnpackedSmallerThan(
        first: JSONPathFilterExpressionValue,
        second: JSONPathFilterExpressionValue,
    ): Boolean = when (first) {
        is JSONPathFilterExpressionValue.StringValue -> if (second is JSONPathFilterExpressionValue.StringValue) {
            first.string.isLexicographicallySmallerThan(second.string)
        } else false

        is JSONPathFilterExpressionValue.NumberValue -> if (second is JSONPathFilterExpressionValue.NumberValue) {
            first < second
        } else false

        else -> false
    }

    override fun visitTestExpr(ctx: JSONPathParser.TestExprContext): Boolean {
        val negate = ctx.LOGICAL_NOT_OP() != null
        val expressionEvaluator = JSONPathFilterExpressionEvaluator(
            rootNode = rootNode,
            currentNode = currentNode,
            functionExtensions = functionExtensions,
        )
        val result =
            expressionEvaluator.visitChildren(ctx)?.isMatch() ?: throw UnexpectedTokenException(ctx)
        return if (negate) {
            !result
        } else {
            result
        }
    }
}

// If the function's declared result type is ValueType, its
//   use in a test expression is not well-typed (see Section 2.4.3).
private fun JSONPathFilterExpressionValue.isMatch(): Boolean {
    return when (this) {
        is JSONPathFilterExpressionValue.LogicalValue -> this.isTrue
        is JSONPathFilterExpressionValue.NodeListValue -> this.nodeList.isNotEmpty()
        else -> TODO("Throw parser exception")
    }
}

private fun JSONPathFilterExpressionValue.isEmptyOrNothing(): Boolean = when (this) {
    is JSONPathFilterExpressionValue.NodeListValue -> this.nodeList.isEmpty()
    JSONPathFilterExpressionValue.Nothing -> true
    else -> false
}

// When any query or function expression on either side of a comparison
// results in a nodelist consisting of a single node, that side is
// replaced by the value of its node.
// source: https://datatracker.ietf.org/doc/rfc9535/
private fun JSONPathFilterExpressionValue.toComparisonValue(): JSONPathFilterExpressionValue =
    when (this) {
        is JSONPathFilterExpressionValue.NodeListValue -> if (this.nodeList.size == 1) {
            this.nodeList[0].toJSONPathFilterExpressionValue()
        } else this

        else -> this
    }