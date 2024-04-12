//package at.asitplus.wallet.lib.data
//
//import at.asitplus.parser.generated.JSONPathBaseVisitor
//import at.asitplus.parser.generated.JSONPathParser
//import io.ktor.http.quote
//import kotlinx.serialization.json.JsonArray
//import kotlinx.serialization.json.JsonElement
//import kotlinx.serialization.json.JsonNull
//import kotlinx.serialization.json.JsonObject
//import kotlinx.serialization.json.JsonPrimitive
//import kotlinx.serialization.json.booleanOrNull
//import kotlinx.serialization.json.buildJsonArray
//import kotlinx.serialization.json.double
//import kotlinx.serialization.json.doubleOrNull
//import org.antlr.v4.kotlinruntime.tree.TerminalNode
//import kotlin.math.max
//import kotlin.math.min
//
///*
//https://datatracker.ietf.org/doc/html/rfc7493
//https://datatracker.ietf.org/doc/rfc9535/
//https://datatracker.ietf.org/doc/html/rfc8259
// */
//
//fun JsonElement.matchJsonPath(
//    jsonPath: String
//): NodeList {
//    var matches = listOf(
//        NodeListEntry(
//            querySegments = listOf(),
//            value = this,
//        )
//    )
//    JSONPathToJSONPathSelectorListCompiler().compile(jsonPath)?.forEach { selector ->
//        matches = matches.flatMap { match ->
//            selector.invoke(
//                rootNode = this,
//                currentNode = match.value
//            ).map { newMatch ->
//                NodeListEntry(
//                    querySegments = match.querySegments + newMatch.querySegments,
//                    value = newMatch.value
//                )
//            }
//        }
//    }
//    return matches
//}
//
//typealias NodeList = List<NodeListEntry>
//
//data class NodeListEntry(
//    // can be an integer for index selectors, or a string for member selectors
//    val querySegments: List<JsonPrimitive>,
//    val value: JsonElement,
//)
//
//sealed interface JSONPathSelector {
//
//    fun invoke(
//        rootNode: JsonElement,
//        currentNode: JsonElement,
//    ): NodeList
//
//    class RootSelector : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return listOf(
//                NodeListEntry(
//                    querySegments = listOf(),
//                    value = currentNode
//                )
//            )
//        }
//    }
//
//    class WildCardSelector : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> currentNode.mapIndexed { index, it ->
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(index)),
//                        value = it,
//                    )
//                }
//
//                is JsonObject -> currentNode.entries.map {
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(it.key)),
//                        value = it.value,
//                    )
//                }
//            }
//        }
//    }
//
//    class MemberSelector(val memberName: String) : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> listOf()
//
//                is JsonObject -> listOfNotNull(currentNode[memberName]?.let {
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(memberName)),
//                        value = it
//                    )
//                })
//            }
//        }
//    }
//
//    class UnionSelector(
//        val selectors: List<JSONPathSelector>
//    ) : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return selectors.map {
//                it.invoke(
//                    rootNode = rootNode,
//                    currentNode = currentNode,
//                )
//            }.flatten()
//        }
//    }
//
//    class SliceSelector(
//        val startInclusive: Int? = null,
//        val endExclusive: Int? = null,
//        val step: Int? = null
//    ) : JSONPathSelector {
//        // source: section 2.3.4.2.2 of https://datatracker.ietf.org/doc/rfc9535/
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> {
//                    // The default value for step is 1.
//                    val actualStepSize = step ?: 1
//
//                    // When step is 0, no elements are selected.
//                    if (actualStepSize == 0) return listOf()
//
//                    // default start and end according to specification
//                    val start = startInclusive
//                        ?: if (actualStepSize > 0) 0 else currentNode.size - 1
//                    val end = endExclusive
//                        ?: if (actualStepSize > 0) currentNode.size else -currentNode.size - 1
//
//                    val (lower, upper) = bounds(start, end, actualStepSize, currentNode.size)
//
//                    val range = if (actualStepSize > 0) {
//                        lower..<upper step actualStepSize
//                    } else {
//                        upper downTo lower + 1 step actualStepSize
//                    }
//
//                    range.map { index ->
//                        currentNode.getOrNull(index)
//                    }.filterNotNull().mapIndexed { index, it ->
//                        NodeListEntry(
//                            querySegments = listOf(JsonPrimitive(index.toString())),
//                            value = it
//                        )
//                    }
//                }
//
//                is JsonObject -> listOf()
//            }
//        }
//
//        private fun normalize(index: Int, arrayLength: Int): Int {
//            return if (index >= 0) {
//                index
//            } else {
//                arrayLength + index
//            }
//        }
//
//        private fun bounds(start: Int, end: Int, stepSize: Int, arrayLength: Int): Pair<Int, Int> {
//            val normalizedStart = normalize(start, arrayLength)
//            val normalizedEnd = normalize(end, arrayLength)
//
//            // bounds implementation according to specification
//            // TODO: need to test whether this yields expected results
//            return if (stepSize >= 0) {
//                val lower = min(max(normalizedStart, 0), arrayLength)
//                val upper = min(max(normalizedEnd, 0), arrayLength)
//                lower to upper
//            } else {
//                val upper = min(max(normalizedStart, -1), arrayLength - 1)
//                val lower = min(max(normalizedEnd, -1), arrayLength - 1)
//                lower to upper
//            }
//        }
//    }
//
//    class IndexSelector(val index: Int) : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> listOfNotNull(
//                    currentNode.getOrNull(index)?.let {
//                        NodeListEntry(
//                            querySegments = listOf(JsonPrimitive(index.toString())),
//                            value = it
//                        )
//                    }
//                )
//
//
//                is JsonObject -> listOf()
//            }
//        }
//    }
//
//    class DescendantSelector() : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> listOf(
//                    NodeListEntry(
//                        querySegments = listOf(),
//                        value = currentNode
//                    )
//                ) + currentNode.mapIndexed { index, it ->
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(index.toString())),
//                        value = it
//                    )
//                }
//
//
//                is JsonObject -> listOf()
//            }
//        }
//    }
//
//    class FilterSelector(
//        val ctx: JSONPathParser.LogicalExprContext,
//        val functionExtensions: Map<String, FunctionExtensionEvaluator>,
//    ) : JSONPathSelector {
//        override fun invoke(
//            rootNode: JsonElement,
//            currentNode: JsonElement,
//        ): NodeList {
//            return when (currentNode) {
//                is JsonPrimitive -> listOf()
//
//                is JsonArray -> currentNode.mapIndexed { index, it ->
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(index.toString())),
//                        value = it
//                    )
//                }
//
//                is JsonObject -> currentNode.entries.map {
//                    NodeListEntry(
//                        querySegments = listOf(JsonPrimitive(it.key)),
//                        value = it.value
//                    )
//                }
//            }.filter {
//                JSONPathExpressionEvaluator(
//                    rootNode = rootNode,
//                    currentNode = it.value,
//                    functionExtensions = functionExtensions,
//                ).visitLogicalExpr(
//                    ctx
//                ).isMatch()
//            }
//        }
//    }
//}
//
//private class JSONPathExpressionEvaluator(
//    val rootNode: JsonElement,
//    val currentNode: JsonElement,
//    val functionExtensions: Map<String, FunctionExtensionEvaluator>
//) : JSONPathBaseVisitor<JSONPathFilterValue>() {
//    // source: https://datatracker.ietf.org/doc/rfc9535/
//
//    override fun visitLogicalOrExpr(ctx: JSONPathParser.LogicalOrExprContext): JSONPathFilterValue {
//        return JSONPathFilterValue.LogicalValue(
//            ctx.logicalAndExpr().any {
//                visitLogicalAndExpr(it).isMatch()
//            }
//        )
//    }
//
//    override fun visitLogicalAndExpr(ctx: JSONPathParser.LogicalAndExprContext): JSONPathFilterValue {
//        return JSONPathFilterValue.LogicalValue(
//            ctx.basicExpr().all {
//                visitBasicExpr(it).isMatch()
//            }
//        )
//    }
//
//    override fun visitParenExpr(ctx: JSONPathParser.ParenExprContext): JSONPathFilterValue {
//        val negate = ctx.LOGICAL_NOT_OP() != null
//        val evaluation = visitLogicalExpr(ctx.logicalExpr()).isMatch()
//        return JSONPathFilterValue.LogicalValue(
//            if (negate) {
//                !evaluation
//            } else {
//                evaluation
//            }
//        )
//    }
//
//    override fun visitComparisonExpr(ctx: JSONPathParser.ComparisonExprContext): JSONPathFilterValue {
//        // see section 2.3.5.2.2 in https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
//
//        // per grammar specification there are exactly two comparables
//        val firstComparable = visitComparable(ctx.comparable(0)!!)
//        val secondComparable = visitComparable(ctx.comparable(1)!!)
//        val comparisonResult = when (ctx.COMPARISON_OP().text) {
//            "==" -> evaluateComparisonEquals(firstComparable, secondComparable)
//
//            "!=" -> !evaluateComparisonEquals(firstComparable, secondComparable)
//
//            "<=" -> evaluateComparisonSmallerThan(
//                firstComparable,
//                secondComparable
//            ) or evaluateComparisonEquals(
//                firstComparable,
//                secondComparable
//            )
//
//            ">=" -> !evaluateComparisonSmallerThan(firstComparable, secondComparable)
//
//            "<" -> evaluateComparisonSmallerThan(firstComparable, secondComparable)
//
//            ">" -> !evaluateComparisonSmallerThan(
//                firstComparable,
//                secondComparable
//            ) and !evaluateComparisonEquals(
//                firstComparable,
//                secondComparable
//            )
//
//            else -> throw InvalidTokenException(ctx.COMPARISON_OP())
//        }
//
//        return JSONPathFilterValue.LogicalValue(comparisonResult)
//    }
//
//    fun evaluateComparisonEquals(
//        first: JSONPathFilterValue,
//        second: JSONPathFilterValue,
//    ): Boolean {
//        // see section 2.3.5.2.2 in https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
//        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) {
//            return first.isEmptyOrNothing() != second.isEmptyOrNothing()
//        }
//
//        return evaluateComparisonUnpackedEquals(
//            first.toComparisonValue(),
//            second.toComparisonValue(),
//        )
//    }
//
//    fun evaluateComparisonUnpackedEquals(
//        first: JSONPathFilterValue,
//        second: JSONPathFilterValue,
//    ): Boolean = when (first) {
//        is JSONPathFilterValue.RealNumberValue -> if (second is JSONPathFilterValue.RealNumberValue) {
//            first.double == second.double
//        } else false
//
//        is JSONPathFilterValue.StringValue -> if (second is JSONPathFilterValue.StringValue) {
//            first.string == second.string
//        } else false
//
//        is JSONPathFilterValue.LogicalValue -> if (second is JSONPathFilterValue.LogicalValue) {
//            first.isTrue == second.isTrue
//        } else false
//
//        is JSONPathFilterValue.JsonObjectValue -> if (second is JSONPathFilterValue.JsonObjectValue) {
//            (first.jsonObject.keys == second.jsonObject.keys) and first.jsonObject.entries.all {
//                evaluateComparisonUnpackedEquals(
//                    it.value.toJSONPathFilterValue(),
//                    // !! because keys are the same as per the wrapping if-else
//                    second.jsonObject[it.key]!!.toJSONPathFilterValue(),
//                )
//            }
//        } else false
//
//        is JSONPathFilterValue.JsonArrayValue -> if (second is JSONPathFilterValue.JsonArrayValue) {
//            (first.jsonArray.size == second.jsonArray.size) and first.jsonArray.mapIndexed { index, it ->
//                index to it
//            }.all {
//                evaluateComparisonUnpackedEquals(
//                    it.second.toJSONPathFilterValue(),
//                    second.jsonArray[it.first].toJSONPathFilterValue(),
//                )
//            }
//        } else false
//
//        is JSONPathFilterValue.NodeListValue -> if (second is JSONPathFilterValue.NodeListValue) {
//            evaluateComparisonUnpackedEquals(
//                JSONPathFilterValue.JsonArrayValue(buildJsonArray {
//                    first.nodeList.forEach { add(it) }
//                }),
//                JSONPathFilterValue.JsonArrayValue(buildJsonArray {
//                    second.nodeList.forEach { add(it) }
//                }),
//            )
//        } else false
//
//        JSONPathFilterValue.Nothing -> throw AssertionError("first should not be Nothing at this point")
//    }
//
//    fun evaluateComparisonSmallerThan(
//        first: JSONPathFilterValue,
//        second: JSONPathFilterValue,
//    ): Boolean {
//        if (first.isEmptyOrNothing() or second.isEmptyOrNothing()) return false
//
//        return evaluateComparisonUnpackedSmallerThan(
//            first.toComparisonValue(),
//            second.toComparisonValue(),
//        )
//    }
//
//    fun evaluateComparisonUnpackedSmallerThan(
//        first: JSONPathFilterValue,
//        second: JSONPathFilterValue,
//    ): Boolean = when (first) {
//        is JSONPathFilterValue.StringValue -> if (second is JSONPathFilterValue.StringValue) {
//            first.string.isLexicographicallySmallerThan(second.string)
//        } else false
//
//        is JSONPathFilterValue.RealNumberValue -> if (second is JSONPathFilterValue.RealNumberValue) {
//            first.double < second.double
//        } else false
//
//        else -> false
//    }
//
//    override fun visitTestExpr(ctx: JSONPathParser.TestExprContext): JSONPathFilterValue {
//        TODO()
//    }
//
//    override fun visitFunctionExpr(ctx: JSONPathParser.FunctionExprContext): JSONPathFilterValue {
//        val functionExtensionName = ctx.functionName().text
//        return functionExtensions[functionExtensionName]?.invoke(
//            ctx.functionArgument().map {
//                visitFunctionArgument(it)
//            }
//        ) ?: throw UnknownFunctionExtensionException(functionExtensionName)
//    }
//
//    override fun visitRelSingularQuery(ctx: JSONPathParser.RelSingularQueryContext): JSONPathFilterValue {
//        val value =
//            currentNode.matchJsonPath("$" + ctx.singularQuerySegments().text).firstOrNull()?.value
//        return when (value) {
//            null -> JSONPathFilterValue.Nothing
//            else -> value.toJSONPathFilterValue()
//        }
//    }
//
//    override fun visitNumber(ctx: JSONPathParser.NumberContext): JSONPathFilterValue {
//        // TODO: support more complex number formats like ParametrizedValue
//        return JSONPathFilterValue.RealNumberValue.DoubleValue(
//            ctx.text.toDouble()
//        )
//    }
//
//    override fun visitStringLiteral(ctx: JSONPathParser.StringLiteralContext): JSONPathFilterValue {
//        return JSONPathFilterValue.StringValue(
//            ctx.toUnescapedString()
//        )
//    }
//
//    override fun visitNull(ctx: JSONPathParser.NullContext): JSONPathFilterValue {
//        return JSONPathFilterValue.Nothing
//    }
//
//    override fun visitTrue(ctx: JSONPathParser.TrueContext): JSONPathFilterValue {
//        return JSONPathFilterValue.LogicalValue(true)
//    }
//
//    override fun visitFalse(ctx: JSONPathParser.FalseContext): JSONPathFilterValue {
//        return JSONPathFilterValue.LogicalValue(false)
//    }
//}
//
//sealed class JSONPathFilterValue {
//    object Nothing : JSONPathFilterValue()
//    class LogicalValue(val isTrue: Boolean) : JSONPathFilterValue()
//    class NodeListValue(val nodeList: List<JsonElement>) : JSONPathFilterValue()
//    sealed class ValueType : JSONPathFilterValue() {
//
//    }
//    class JsonValue(val jsonElement: JsonElement) : ValueType()
//    class StringValue(val string: String) : JSONPathFilterValue()
//    class JsonObjectValue(val jsonObject: JsonObject) : JSONPathFilterValue()
//    class JsonArrayValue(val jsonArray: JsonArray) : JSONPathFilterValue()
//
//    fun isMatch(): Boolean {
//        // If the function's declared result type is ValueType, its
//        //   use in a test expression is not well-typed (see Section 2.4.3).
//        return when (this) {
//            is LogicalValue -> this.isTrue
//            is NodeListValue -> this.nodeList.isNotEmpty()
//            Nothing -> false
//            else -> TODO("Throw parser exception")
//        }
//    }
//
//    fun isEmptyOrNothing(): Boolean = when (this) {
//        is NodeListValue -> this.nodeList.isEmpty()
//        Nothing -> true
//        else -> false
//    }
//
//    // When any query or function expression on either side of a comparison
//    // results in a nodelist consisting of a single node, that side is
//    // replaced by the value of its node and then:
//    fun toComparisonValue(): JSONPathFilterValue = when (this) {
//        is NodeListValue -> if (this.nodeList.size == 1) {
//            this.nodeList[0].toJSONPathFilterValue()
//        } else this
//
//        else -> this
//    }
//}
//
//private fun JsonElement.toJSONPathFilterValue(): JSONPathFilterValue {
//    return when (this) {
//        is JsonArray -> JSONPathFilterValue.JsonArrayValue(this)
//        is JsonObject -> JSONPathFilterValue.JsonObjectValue(this)
//        is JsonPrimitive -> if (this.isString) {
//            JSONPathFilterValue.StringValue(this.content)
//        } else this.booleanOrNull?.let {
//            JSONPathFilterValue.LogicalValue(it)
//        } ?: this.doubleOrNull!!.let {
//            // no need to treat longs differently
//            // source: https://datatracker.ietf.org/doc/html/rfc7493#section-2.2
//            //    An I-JSON sender cannot expect a receiver to treat an integer whose
//            //   absolute value is greater than 9007199254740991 (i.e., that is
//            //   outside the range [-(2**53)+1, (2**53)-1]) as an exact value.
//            JSONPathFilterValue.RealNumberValue(it)
//        }
//
//        JsonNull -> JSONPathFilterValue.Nothing
//    }
//}
//
//interface FunctionExtensionEvaluator {
//    fun invoke(arguments: List<JSONPathFilterValue>): JSONPathFilterValue
//}
//
//class UnknownFunctionExtensionException(functionExtensionName: String) :
//    Exception(functionExtensionName)
//
//
////
////
////sealed class JSONPathExpressionValue {
////    sealed class ValueType : JSONPathExpressionValue() {
////        class Nothing : ValueType()
////
////        // LogicalType values are represented as boolean JsonPrimitives
////        class JsonValue(val jsonElement: JsonElement) : ValueType()
////    }
////
////    class NodesType(val nodeList: NodeList) : JSONPathExpressionValue()
////
////    fun toBoolean(): Boolean {
////        // If the function's declared result type is ValueType, its
////        //   use in a test expression is not well-typed (see Section 2.4.3).
////        when (this) {
////            is NodesType -> this.nodeList.isNotEmpty()
////            is ValueType.JsonValue -> when (jsonElement) {
////                is JsonArray -> TODO()
////                is JsonObject -> TODO()
////                is JsonPrimitive -> TODO()
////                JsonNull -> TODO()
////            }
////
////            is ValueType.Nothing -> TODO()
////        }
////    }
////
////    val isEmptyOrNothing = when (this) {
////        is NodesType -> this.nodeList.isEmpty()
////        is ValueType.Nothing -> true
////        else -> false
////    }
////
////    // When any query or function expression on either side of a comparison
////    // results in a nodelist consisting of a single node, that side is
////    // replaced by the value of its node and then:
////    val comparisonValue = when (this) {
////        is NodesType -> if (this.nodeList.size == 1) {
////            ValueType.JsonValue(this.nodeList[0].value)
////        } else this
////
////        else -> this
////    }
////}
//
//class InvalidJSONPathLogicalExpression(logicalExprContext: JSONPathParser.LogicalExprContext) :
//    Exception(logicalExprContext.text)
//
//class InvalidTokenException(
//    node: TerminalNode
//) : Exception("Unexpected text between character ${node.sourceInterval.a} and ${node.sourceInterval.b}: \"${node.text.quote()}\"")
//
//fun String.isLexicographicallySmallerThan(other: String): Boolean {
//    return if (this.isEmpty()) {
//        other.isNotEmpty()
//    } else if (other.isEmpty()) {
//        false
//    } else if (this[0] < other[0]) {
//        true
//    } else {
//        (this[0] == other[0]) and this.substring(1)
//            .isLexicographicallySmallerThan(other.substring(1))
//    }
//}
//
//sealed class JSONPathFunctionExpressionReturnType {
//    class ValueType : JSONPathFunctionExpressionReturnType()
//    class LogicalType : JSONPathFunctionExpressionReturnType()
//    class NodeType : JSONPathFunctionExpressionReturnType()
//}