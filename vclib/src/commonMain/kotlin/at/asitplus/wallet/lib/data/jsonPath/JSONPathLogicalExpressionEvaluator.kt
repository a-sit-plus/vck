//package at.asitplus.wallet.lib.data.jsonPath
//
//import at.asitplus.parser.generated.JSONPathBaseVisitor
//import at.asitplus.parser.generated.JSONPathParser
//import kotlinx.serialization.json.JsonElement
//import kotlinx.serialization.json.buildJsonArray
//
//internal class JSONPathLogicalExpressionEvaluator(
//    val rootNode: JsonElement,
//    val currentNode: JsonElement,
//    val functionExtensionManager: JSONPathFunctionExtensionManager,
//) : JSONPathBaseVisitor<Boolean>() {
//    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
//
//    override fun visitLogical_or_expr(ctx: JSONPathParser.Logical_or_exprContext): Boolean {
//        return ctx.logical_and_expr().any {
//            visitLogical_and_expr(it)
//        }
//    }
//
//    override fun visitLogical_and_expr(ctx: JSONPathParser.Logical_and_exprContext): Boolean {
//        return ctx.basic_expr().all {
//            visitBasic_expr(it)
//        }
//    }
//
//    override fun visitParen_expr(ctx: JSONPathParser.Paren_exprContext): Boolean {
//        val negate = ctx.LOGICAL_NOT_OP() != null
//        val evaluation = visitLogical_expr(ctx.logical_expr())
//        return if (negate) {
//            !evaluation
//        } else {
//            evaluation
//        }
//    }
//
//    override fun visitComparison_expr(ctx: JSONPathParser.Comparison_exprContext): Boolean {
//        // see section 2.3.5.2.2
//        val expressionEvaluator = JSONPathExpressionEvaluator(
//            rootNode = rootNode,
//            currentNode = currentNode,
//            functionExtensionManager = functionExtensionManager,
//        )
//        val firstComparable =
//            expressionEvaluator.visitComparable(
//                ctx.comparable(0) ?: throw UnexpectedTokenException(ctx)
//            )
//        val secondComparable =
//            expressionEvaluator.visitComparable(
//                ctx.comparable(1) ?: throw UnexpectedTokenException(ctx)
//            )
//        val comparisonResult = ctx.comparisonOp().let {
//            when {
//                it.equalsOp() != null -> this.evaluateComparisonEquals(
//                    firstComparable,
//                    secondComparable
//                )
//
//                it.smallerThanOp() != null -> evaluateComparisonSmallerThan(
//                    firstComparable,
//                    secondComparable
//                )
//
//                it.notEqualsOp() != null -> !this.evaluateComparisonEquals(
//                    firstComparable,
//                    secondComparable
//                )
//
//                it.smallerThanOrEqualsOp() != null -> evaluateComparisonSmallerThan(
//                    firstComparable,
//                    secondComparable
//                ) or this.evaluateComparisonEquals(
//                    firstComparable,
//                    secondComparable
//                )
//
//                it.greaterThanOp() != null -> evaluateComparisonSmallerThan(
//                    secondComparable,
//                    firstComparable,
//                )
//
//                it.greaterThanOrEqualsOp() != null -> evaluateComparisonSmallerThan(
//                    secondComparable,
//                    firstComparable,
//                ) or this.evaluateComparisonEquals(
//                    firstComparable,
//                    secondComparable
//                )
//
//                else -> throw UnexpectedTokenException(ctx.comparisonOp())
//            }
//        }
//
//        return comparisonResult
//    }
//
//    internal fun evaluateComparisonEquals(
//        first: JSONPathExpressionValue,
//        second: JSONPathExpressionValue,
//    ): Boolean {
//        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) return false
//
//        return evaluateComparisonEqualsUnpacked(
//            first.toComparisonValue(),
//            second.toComparisonValue(),
//        )
//    }
//
//    internal fun evaluateComparisonEqualsUnpacked(
//        first: JSONPathExpressionValue,
//        second: JSONPathExpressionValue,
//    ): Boolean = when (first) {
//        is JSONPathExpressionValue.NumberValue -> if (second is JSONPathExpressionValue.NumberValue) {
//            first == second
//        } else false
//
//        is JSONPathExpressionValue.StringValue -> if (second is JSONPathExpressionValue.StringValue) {
//            first.string == second.string
//        } else false
//
//        is JSONPathExpressionValue.LogicalValue -> if (second is JSONPathExpressionValue.LogicalValue) {
//            first.isTrue == second.isTrue
//        } else false
//
//        is JSONPathExpressionValue.JsonObjectValue -> if (second is JSONPathExpressionValue.JsonObjectValue) {
//            (first.jsonObject.keys == second.jsonObject.keys) and first.jsonObject.entries.all {
//                this.evaluateComparisonEqualsUnpacked(
//                    it.value.toJSONPathFilterExpressionValue(),
//                    second.jsonObject[it.key]?.toJSONPathFilterExpressionValue()
//                        ?: throw MissingKeyException(
//                            jsonObject = second.jsonObject,
//                            key = it.key
//                        ),
//                )
//            }
//        } else false
//
//        is JSONPathExpressionValue.JsonArrayValue -> if (second is JSONPathExpressionValue.JsonArrayValue) {
//            (first.jsonArray.size == second.jsonArray.size) and first.jsonArray.mapIndexed { index, it ->
//                index to it
//            }.all {
//                this.evaluateComparisonEqualsUnpacked(
//                    it.second.toJSONPathFilterExpressionValue(),
//                    second.jsonArray[it.first].toJSONPathFilterExpressionValue(),
//                )
//            }
//        } else false
//
//        is JSONPathExpressionValue.NodeListValue -> if (first.nodeList.isEmpty()) {
//            second.isEmptyOrNothing()
//        } else if (second is JSONPathExpressionValue.NodeListValue) {
//            this.evaluateComparisonEqualsUnpacked(
//                JSONPathExpressionValue.JsonArrayValue(buildJsonArray {
//                    first.nodeList.forEach { add(it) }
//                }),
//                JSONPathExpressionValue.JsonArrayValue(buildJsonArray {
//                    second.nodeList.forEach { add(it) }
//                }),
//            )
//        } else false
//
//        JSONPathExpressionValue.NullValue -> second is JSONPathExpressionValue.NullValue
//        JSONPathExpressionValue.Nothing -> second.isEmptyOrNothing()
//    }
//
//    internal fun evaluateComparisonSmallerThan(
//        first: JSONPathExpressionValue,
//        second: JSONPathExpressionValue,
//    ): Boolean {
//        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) return false
//
//        return evaluateComparisonUnpackedSmallerThan(
//            first.toComparisonValue(),
//            second.toComparisonValue(),
//        )
//    }
//
//    internal fun evaluateComparisonUnpackedSmallerThan(
//        first: JSONPathExpressionValue,
//        second: JSONPathExpressionValue,
//    ): Boolean = when (first) {
//        is JSONPathExpressionValue.StringValue -> if (second is JSONPathExpressionValue.StringValue) {
//            first.string.isLexicographicallySmallerThan(second.string)
//        } else false
//
//        is JSONPathExpressionValue.NumberValue -> if (second is JSONPathExpressionValue.NumberValue) {
//            first < second
//        } else false
//
//        else -> false
//    }
//
//    override fun visitTest_expr(ctx: JSONPathParser.Test_exprContext): Boolean {
//        val negate = ctx.LOGICAL_NOT_OP() != null
//        val expressionEvaluator = JSONPathExpressionEvaluator(
//            rootNode = rootNode,
//            currentNode = currentNode,
//            functionExtensionManager = functionExtensionManager,
//        )
//        val result =
//            expressionEvaluator.visitChildren(ctx)?.isMatch() ?: throw UnexpectedTokenException(ctx)
//        return if (negate) {
//            !result
//        } else {
//            result
//        }
//    }
//}
//
//// If the function's declared result type is ValueType, its
////   use in a test expression is not well-typed (see Section 2.4.3).
//private fun JSONPathExpressionValue.isMatch(): Boolean {
//    return when (this) {
//        is JSONPathExpressionValue.LogicalValue -> this.isTrue
//        is JSONPathExpressionValue.NodeListValue -> this.nodeList.isNotEmpty()
//        else -> TODO("Throw parser exception")
//    }
//}
//
//private fun JSONPathExpressionValue.isEmptyOrNothing(): Boolean = when (this) {
//    is JSONPathExpressionValue.NodeListValue -> this.nodeList.isEmpty()
//    JSONPathExpressionValue.Nothing -> true
//    else -> false
//}
//
//// When any query or function expression on either side of a comparison
//// results in a nodelist consisting of a single node, that side is
//// replaced by the value of its node.
//// source: https://datatracker.ietf.org/doc/rfc9535/
//private fun JSONPathExpressionValue.toComparisonValue(): JSONPathExpressionValue =
//    when (this) {
//        is JSONPathExpressionValue.NodeListValue -> if (this.nodeList.size == 1) {
//            this.nodeList[0].toJSONPathFilterExpressionValue()
//        } else this
//
//        else -> this
//    }
