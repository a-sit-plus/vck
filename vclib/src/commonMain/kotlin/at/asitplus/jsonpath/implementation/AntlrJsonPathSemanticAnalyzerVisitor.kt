package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.FilterPredicate
import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFilterExpressionValue
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import at.asitplus.jsonpath.core.JsonPathSelector
import at.asitplus.jsonpath.core.JsonPathSelectorQuery
import at.asitplus.jsonpath.generated.JsonPathParser
import at.asitplus.jsonpath.generated.JsonPathParserBaseVisitor
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.longOrNull
import org.antlr.v4.kotlinruntime.ParserRuleContext
import org.antlr.v4.kotlinruntime.tree.TerminalNode

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 * section 2.4.3: Well-Typedness of Function Expressions
 *
 * This class builds an abstract syntax tree where the nodes contain the logic necessary to be evaluated against an input.
 */
internal class AntlrJsonPathSemanticAnalyzerVisitor(
    private val errorListener: AntlrJsonPathSemanticAnalyzerErrorListener?,
    private val functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
) : JsonPathParserBaseVisitor<AbstractSyntaxTree<out JsonPathExpression>>() {
    override fun defaultResult(): AbstractSyntaxTree<JsonPathExpression> {
        return AbstractSyntaxTree(context = null, value = JsonPathExpression.NoType)
    }

    override fun visitTerminal(node: TerminalNode): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(token = node.symbol, value = JsonPathExpression.NoType)
    }

    override fun aggregateResult(
        aggregate: AbstractSyntaxTree<out JsonPathExpression>?,
        nextResult: AbstractSyntaxTree<out JsonPathExpression>
    ): AbstractSyntaxTree<out JsonPathExpression> {
        val children = (aggregate?.children ?: listOf()) + nextResult
        return AbstractSyntaxTree(
            context = null,
            value = if (children.any { it.value is JsonPathExpression.ErrorType }) {
                JsonPathExpression.ErrorType
            } else {
                when (aggregate?.value) {
                    is JsonPathExpression.ErrorType -> {
                        JsonPathExpression.ErrorType
                    }

                    null, is JsonPathExpression.NoType -> {
                        nextResult.value
                    }

                    else -> if (nextResult.value is JsonPathExpression.NoType) {
                        // don't override a value with no value
                        aggregate.value
                    } else {
                        // this is not generalizable anyway and needs to be handeled for each node explicitly
                        nextResult.value
                    }
                }
            },
            children = children
        )
    }

    // queries
    override fun visitJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext): AbstractSyntaxTree<out JsonPathExpression> {
        return QueryNodeBuilder(
            context = ctx,
            contextSelectorNode = visitRootIdentifier(ctx.rootIdentifier()),
            selectorSegmentTrees = ctx.segments().segment().map { visitSegment(it) }
        ).build()
    }

    override fun visitRel_query(ctx: JsonPathParser.Rel_queryContext): AbstractSyntaxTree<out JsonPathExpression> {
        return QueryNodeBuilder(
            context = ctx,
            contextSelectorNode = visitCurrentNodeIdentifier(ctx.currentNodeIdentifier()),
            selectorSegmentTrees = ctx.segments().segment().map { visitSegment(it) }
        ).build()
    }

    override fun visitAbs_singular_query(ctx: JsonPathParser.Abs_singular_queryContext): AbstractSyntaxTree<out JsonPathExpression> {
        return QueryNodeBuilder(
            context = ctx,
            contextSelectorNode = visitRootIdentifier(ctx.rootIdentifier()),
            selectorSegmentTrees = ctx.singular_query_segments().singular_query_segment().map {
                visitSingular_query_segment(it)
            },
        ).build()
    }

    override fun visitRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext): AbstractSyntaxTree<out JsonPathExpression> {
        return QueryNodeBuilder(
            context = ctx,
            contextSelectorNode = visitCurrentNodeIdentifier(ctx.currentNodeIdentifier()),
            selectorSegmentTrees = ctx.singular_query_segments().singular_query_segment().map {
                visitSingular_query_segment(it)
            },
        ).build()
    }

    // selectors
    override fun visitRootIdentifier(ctx: JsonPathParser.RootIdentifierContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(JsonPathSelector.RootSelector)
        )
    }

    override fun visitCurrentNodeIdentifier(ctx: JsonPathParser.CurrentNodeIdentifierContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(JsonPathSelector.CurrentNodeSelector),
        )
    }

    override fun visitMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(
                JsonPathSelector.MemberSelector(ctx.MEMBER_NAME_SHORTHAND().text),
            ),
        )
    }

    override fun visitName_selector(ctx: JsonPathParser.Name_selectorContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(
                JsonPathSelector.MemberSelector(
                    ctx.stringLiteral().toUnescapedString()
                )
            )
        )
    }

    override fun visitIndex_selector(ctx: JsonPathParser.Index_selectorContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(
                JsonPathSelector.IndexSelector(
                    ctx.int().INT().text.toInt()
                )
            )
        )
    }

    override fun visitSlice_selector(ctx: JsonPathParser.Slice_selectorContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(
                JsonPathSelector.SliceSelector(
                    startInclusive = ctx.start()?.text?.toInt(),
                    endExclusive = ctx.end()?.text?.toInt(),
                    step = ctx.step()?.text?.toInt(),
                )
            )
        )
    }

    override fun visitWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext): AbstractSyntaxTree<JsonPathExpression.SelectorExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.SelectorExpression(
                JsonPathSelector.WildCardSelector
            )
        )
    }

    override fun visitDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext): AbstractSyntaxTree<JsonPathExpression> {
        val child = ctx.bracketed_selection()?.let { visitBracketed_selection(it) }
            ?: ctx.memberNameShorthand()?.let { visitMemberNameShorthand(it) }
            ?: ctx.wildcardSelector()?.let { visitWildcardSelector(it) }

        val childValue = child?.value

        return AbstractSyntaxTree(
            context = ctx,
            value = if (childValue is JsonPathExpression.SelectorExpression) {
                JsonPathExpression.SelectorExpression(
                    JsonPathSelector.DescendantSelector(
                        childValue.selector
                    )
                )
            } else JsonPathExpression.ErrorType,
            children = listOfNotNull(child)
        )
    }

    override fun visitBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext): AbstractSyntaxTree<JsonPathExpression> {
        val children = ctx.selector().map {
            visitSelector(it)
        }

        val selectorExpressionChildren = children.map {
            it.value
        }.filterIsInstance<JsonPathExpression.SelectorExpression>()

        return AbstractSyntaxTree(
            context = ctx,
            value = if (selectorExpressionChildren.size == children.size) {
                JsonPathExpression.SelectorExpression(
                    JsonPathSelector.BracketedSelector(
                        selectorExpressionChildren.map { it.selector }
                    )
                )
            } else JsonPathExpression.ErrorType,
            children = children
        )
    }

    override fun visitFilter_selector(ctx: JsonPathParser.Filter_selectorContext): AbstractSyntaxTree<JsonPathExpression> {
        val logicalExpressionNode = visitLogical_expr(ctx.logical_expr())
        return AbstractSyntaxTree(
            context = ctx,
            value = if (logicalExpressionNode.value is JsonPathExpression.FilterExpression.LogicalExpression) {
                JsonPathExpression.SelectorExpression(
                    JsonPathSelector.FilterSelector(
                        object : FilterPredicate {
                            override fun invoke(
                                currentNode: JsonElement,
                                rootNode: JsonElement
                            ): Boolean = logicalExpressionNode.value.evaluate(
                                JsonPathExpressionEvaluationContext(
                                    currentNode = currentNode,
                                    rootNode = rootNode,
                                )
                            ).isTrue
                        }
                    )
                )
            } else JsonPathExpression.ErrorType,
            children = listOf(logicalExpressionNode)
        )
    }

    // logical expressions
    override fun visitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext): AbstractSyntaxTree<JsonPathExpression> {
        val children = ctx.logical_and_expr().map {
            visitLogical_and_expr(it)
        }
        val logicalChildrenValues = children.map { it.value }
            .filterIsInstance<JsonPathExpression.FilterExpression.LogicalExpression>()

        return AbstractSyntaxTree(
            context = ctx,
            value = if (logicalChildrenValues.size == children.size) {
                JsonPathExpression.FilterExpression.LogicalExpression { context ->
                    JsonPathFilterExpressionValue.LogicalTypeValue(
                        logicalChildrenValues.any {
                            it.evaluate(context).isTrue
                        }
                    )
                }
            } else JsonPathExpression.ErrorType,
            children = children,
        )
    }

    override fun visitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext): AbstractSyntaxTree<JsonPathExpression> {
        val children = ctx.basic_expr().map {
            visitBasic_expr(it)
        }
        val logicalChildrenValues = children.map { it.value }
            .filterIsInstance<JsonPathExpression.FilterExpression.LogicalExpression>()

        return AbstractSyntaxTree(
            context = ctx,
            value = if (logicalChildrenValues.size == children.size) {
                JsonPathExpression.FilterExpression.LogicalExpression { context ->
                    JsonPathFilterExpressionValue.LogicalTypeValue(
                        logicalChildrenValues.all {
                            it.evaluate(context).isTrue
                        }
                    )
                }
            } else JsonPathExpression.ErrorType,
            children = children,
        )
    }

    override fun visitParen_expr(ctx: JsonPathParser.Paren_exprContext): AbstractSyntaxTree<JsonPathExpression> {
        val isNotNegated = ctx.LOGICAL_NOT_OP()?.let { false } ?: true
        val child = visitLogical_expr(ctx.logical_expr())
        return AbstractSyntaxTree(
            context = ctx,
            value = if (child.value is JsonPathExpression.FilterExpression.LogicalExpression) {
                JsonPathExpression.FilterExpression.LogicalExpression { context ->
                    JsonPathFilterExpressionValue.LogicalTypeValue(
                        child.value.evaluate(context).isTrue == isNotNegated
                    )
                }
            } else JsonPathExpression.ErrorType,
            children = listOf(child),
        )
    }

    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): AbstractSyntaxTree<out JsonPathExpression> {
        val isNotNegated = (ctx.LOGICAL_NOT_OP() == null)
        return ctx.filter_query()?.let {
            val filterQueryTree = visitFilter_query(it)
            val filterQueryValue = filterQueryTree.value
            AbstractSyntaxTree(
                context = ctx,
                value = if (filterQueryValue is JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression) {
                    JsonPathExpression.FilterExpression.LogicalExpression { context ->
                        JsonPathFilterExpressionValue.LogicalTypeValue(
                            filterQueryValue.jsonPathQuery.invoke(
                                currentNode = context.currentNode,
                                rootNode = context.rootNode
                            ).isNotEmpty() == isNotNegated
                        )
                    }
                } else JsonPathExpression.ErrorType,
                children = listOf(filterQueryTree)
            )
        } ?: ctx.function_expr()?.let { functionExpressionContext ->
            /**
             * specification: https://datatracker.ietf.org/doc/rfc9535/
             * date: 2024-02
             * section 2.4.3: Well-Typedness of Function Expressions
             *
             *        As a test-expr in a logical expression:
             *           The function's declared result type is LogicalType or (giving
             *           rise to conversion as per Section 2.4.2) NodesType.
             */
            val child = visitFunction_expr(functionExpressionContext)
            val functionResultValue = child.value
            AbstractSyntaxTree(
                context = ctx,
                value = when (functionResultValue) {
                    is JsonPathExpression.FilterExpression.ValueExpression -> {
                        JsonPathExpression.ErrorType.also {
                            errorListener?.invalidFunctionExtensionForTestExpression(
                                functionExpressionContext.FUNCTION_NAME().text,
                            )
                        }
                    }

                    is JsonPathExpression.FilterExpression.LogicalExpression -> {
                        JsonPathExpression.FilterExpression.LogicalExpression { context ->
                            JsonPathFilterExpressionValue.LogicalTypeValue(
                                functionResultValue.evaluate(context).isTrue == isNotNegated
                            )
                        }
                    }

                    is JsonPathExpression.FilterExpression.NodesExpression.NodesFunctionExpression -> {
                        JsonPathExpression.FilterExpression.LogicalExpression { context ->
                            JsonPathFilterExpressionValue.LogicalTypeValue(
                                functionResultValue.evaluate(context).nodeList.isNotEmpty() == isNotNegated
                            )
                        }
                    }

                    else -> JsonPathExpression.ErrorType
                },
                children = listOf(child),
            )
        } ?: AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.ErrorType,
        ).also {
            errorListener?.invalidTestExpression(ctx.text)
        }
    }

    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): AbstractSyntaxTree<JsonPathExpression> {
        val functionArgumentNodes = ctx.function_argument().map {
            visitFunction_argument(it)
        }

        val extension = functionExtensionRetriever.invoke(ctx.FUNCTION_NAME().text)
            ?: return AbstractSyntaxTree(
                context = ctx,
                value = JsonPathExpression.ErrorType,
                children = functionArgumentNodes,
            ).also {
                errorListener?.unknownFunctionExtension(ctx.FUNCTION_NAME().text)
            }

        val isArglistSizeConsistent = ctx.function_argument().size == extension.argumentTypes.size
        val coercedArgumentExpressions =
            functionArgumentNodes.map { it.value }.mapIndexed { index, argumentNode ->
                when (extension.argumentTypes.getOrNull(index)) {
                    /**
                     * specification: https://datatracker.ietf.org/doc/rfc9535/
                     * date: 2024-02
                     * section 2.4.3: Well-Typedness of Function Expressions
                     *
                     *       *  When the declared type of the parameter is LogicalType and the
                     *           argument is one of the following:
                     *
                     *           -  A function expression with declared result type NodesType.
                     *              In this case, the argument is converted to LogicalType as
                     *              per Section 2.4.2.
                     */
                    JsonPathFilterExpressionType.LogicalType -> when (argumentNode) {
                        is JsonPathExpression.FilterExpression.NodesExpression -> {
                            JsonPathExpression.FilterExpression.LogicalExpression {
                                JsonPathFilterExpressionValue.LogicalTypeValue(
                                    argumentNode.evaluate(it).nodeList.isNotEmpty()
                                )
                            }
                        }

                        else -> argumentNode
                    }

                    JsonPathFilterExpressionType.NodesType -> argumentNode

                    /**
                     * specification: https://datatracker.ietf.org/doc/rfc9535/
                     * date: 2024-02
                     * section 2.4.3: Well-Typedness of Function Expressions
                     *
                     *        *  When the declared type of the parameter is ValueType and the
                     *           argument is one of the following:
                     *
                     *           -  A value expressed as a literal.
                     *
                     *           -  A singular query.  In this case:
                     *
                     *              o  If the query results in a nodelist consisting of a
                     *                 single node, the argument is the value of the node.
                     *
                     *              o  If the query results in an empty nodelist, the argument
                     *                 is the special result Nothing.
                     */
                    JsonPathFilterExpressionType.ValueType -> when (argumentNode) {
                        is JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression.SingularQueryExpression -> {
                            argumentNode.toValueTypeValue()
                        }

                        else -> argumentNode
                    }

                    null -> argumentNode
                }
            }

        val coercedArgumentTypes = coercedArgumentExpressions.map {
            if (it !is JsonPathExpression.FilterExpression) {
                null
            } else {
                it.expressionType
            }
        }

        val isCoercedArgumentTypesMatching =
            coercedArgumentTypes.mapIndexed { index, argumentType ->
                argumentType == extension.argumentTypes[index]
            }.all {
                it
            }

        val isValidFunctionCall =
            isArglistSizeConsistent and isCoercedArgumentTypesMatching

        if (isValidFunctionCall == false) {
            errorListener?.invalidArglistForFunctionExtension(
                functionExtension = extension,
                coercedArgumentTypes = coercedArgumentTypes.zip(
                    functionArgumentNodes.map {
                        it.text
                    }
                )
            )
        }

        return AbstractSyntaxTree(
            context = ctx,
            value = if (isValidFunctionCall) {
                val coercedArguments =
                    coercedArgumentExpressions.filterIsInstance<JsonPathExpression.FilterExpression>()

                when (extension) {
                    is JsonPathFunctionExtension.LogicalTypeFunctionExtension -> {
                        JsonPathExpression.FilterExpression.LogicalExpression { context ->
                            extension.invoke(coercedArguments.map {
                                it.evaluate.invoke(context)
                            })
                        }
                    }

                    is JsonPathFunctionExtension.NodesTypeFunctionExtension -> {
                        JsonPathExpression.FilterExpression.NodesExpression.NodesFunctionExpression { context ->
                            extension.invoke(coercedArguments.map {
                                it.evaluate.invoke(context)
                            })
                        }
                    }

                    is JsonPathFunctionExtension.ValueTypeFunctionExtension -> {
                        JsonPathExpression.FilterExpression.ValueExpression { context ->
                            extension.invoke(coercedArguments.map {
                                it.evaluate.invoke(context)
                            })
                        }
                    }
                }
            } else {
                JsonPathExpression.ErrorType
            },
            children = functionArgumentNodes,
        )
    }

    override fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): AbstractSyntaxTree<JsonPathExpression> {
        val firstComparable = visitComparable(ctx.firstComparable().comparable())
        val secondComparable = visitComparable(ctx.secondComparable().comparable())
        val children = listOf(firstComparable, secondComparable)

        val firstValue =
            if (firstComparable.value is JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression.SingularQueryExpression) {
                firstComparable.value.toValueTypeValue()
            } else firstComparable.value

        val secondValue =
            if (secondComparable.value is JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression.SingularQueryExpression) {
                secondComparable.value.toValueTypeValue()
            } else secondComparable.value

        listOf(
            ctx.firstComparable().comparable() to firstValue,
            ctx.secondComparable().comparable() to secondValue,
        ).forEach { (comparableContext, value) ->
            val functionExpressionContext = comparableContext.function_expr()
            when {
                value is JsonPathExpression.ErrorType -> {}
                functionExpressionContext != null -> {
                    /**
                     * specification: https://datatracker.ietf.org/doc/rfc9535/
                     * date: 2024-02
                     * section 2.4.3: Well-Typedness of Function Expressions
                     *
                     *        As a comparable in a comparison:
                     *           The function's declared result type is ValueType.
                     */
                    if (value !is JsonPathExpression.FilterExpression.ValueExpression) {
                        errorListener?.invalidFunctionExtensionForComparable(
                            functionExpressionContext.FUNCTION_NAME().text,
                        )
                    }
                }
            }
        }

        return AbstractSyntaxTree(
            context = ctx,
            value = if (firstValue !is JsonPathExpression.FilterExpression.ValueExpression) {
                JsonPathExpression.ErrorType
            } else if (secondValue !is JsonPathExpression.FilterExpression.ValueExpression) {
                JsonPathExpression.ErrorType
            } else comparisonExpression(
                firstComparable = firstValue.evaluate,
                secondComparable = secondValue.evaluate,
                ctx.comparisonOp(),
            ),
            children = children,
        )
    }

    private fun comparisonExpression(
        firstComparable: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.ValueTypeValue,
        secondComparable: (JsonPathExpressionEvaluationContext) -> JsonPathFilterExpressionValue.ValueTypeValue,
        comparisonOpContext: JsonPathParser.ComparisonOpContext,
    ): JsonPathExpression = comparisonOpContext.let {
        when {
            it.COMPARISON_OP_EQUALS() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    this.evaluateComparisonEquals(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    )
                )
            }

            it.COMPARISON_OP_SMALLER_THAN() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    evaluateComparisonSmallerThan(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    )
                )
            }

            it.COMPARISON_OP_NOT_EQUALS() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    !this.evaluateComparisonEquals(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    )
                )
            }

            it.COMPARISON_OP_SMALLER_THAN_OR_EQUALS() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    evaluateComparisonSmallerThan(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    ) or this.evaluateComparisonEquals(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    )
                )
            }

            it.COMPARISON_OP_GREATER_THAN() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    evaluateComparisonSmallerThan(
                        secondComparable.invoke(context),
                        firstComparable.invoke(context),
                    )
                )
            }

            it.COMPARISON_OP_GREATER_THAN_OR_EQUALS() != null -> JsonPathExpression.FilterExpression.LogicalExpression { context ->
                JsonPathFilterExpressionValue.LogicalTypeValue(
                    evaluateComparisonSmallerThan(
                        secondComparable.invoke(context),
                        firstComparable.invoke(context),
                    ) or this.evaluateComparisonEquals(
                        firstComparable.invoke(context),
                        secondComparable.invoke(context),
                    )
                )
            }

            else -> JsonPathExpression.ErrorType
        }
    }

    private fun evaluateComparisonEquals(
        firstValue: JsonPathFilterExpressionValue.ValueTypeValue,
        secondValue: JsonPathFilterExpressionValue.ValueTypeValue,
    ): Boolean {
        if (firstValue is JsonPathFilterExpressionValue.ValueTypeValue.Nothing) {
            return secondValue is JsonPathFilterExpressionValue.ValueTypeValue.Nothing
        }
        if (secondValue is JsonPathFilterExpressionValue.ValueTypeValue.Nothing) {
            return false
        }

        return evaluateComparisonEqualsUnpacked(
            firstValue,
            secondValue,
        )
    }

    private fun evaluateComparisonEqualsUnpacked(
        first: JsonPathFilterExpressionValue.ValueTypeValue,
        second: JsonPathFilterExpressionValue.ValueTypeValue,
    ): Boolean = when (first) {
        is JsonPathFilterExpressionValue.ValueTypeValue.JsonValue -> {
            if (second !is JsonPathFilterExpressionValue.ValueTypeValue.JsonValue) {
                false
            } else when (first.jsonElement) {
                JsonNull -> {
                    second.jsonElement == JsonNull
                }

                is JsonPrimitive -> {
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
                }

                is JsonArray -> {
                    if (second.jsonElement is JsonArray) {
                        (first.jsonElement.size == second.jsonElement.size) and first.jsonElement.mapIndexed { index, it ->
                            index to it
                        }.all {
                            this.evaluateComparisonEqualsUnpacked(
                                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(it.second),
                                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(second.jsonElement[it.first]),
                            )
                        }
                    } else false
                }

                is JsonObject -> {
                    if (second.jsonElement is JsonObject) {
                        (first.jsonElement.keys == second.jsonElement.keys) and first.jsonElement.entries.all {
                            this.evaluateComparisonEqualsUnpacked(
                                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(it.value),
                                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                                    second.jsonElement[it.key]
                                        ?: throw MissingKeyException(
                                            jsonObject = second.jsonElement,
                                            key = it.key
                                        )
                                )
                            )
                        }
                    } else false
                }
            }
        }

        JsonPathFilterExpressionValue.ValueTypeValue.Nothing -> second == JsonPathFilterExpressionValue.ValueTypeValue.Nothing
    }

    private fun evaluateComparisonSmallerThan(
        firstValue: JsonPathFilterExpressionValue.ValueTypeValue,
        secondValue: JsonPathFilterExpressionValue.ValueTypeValue,
    ): Boolean {
        if (firstValue is JsonPathFilterExpressionValue.ValueTypeValue.Nothing) {
            return false
        }
        if (secondValue is JsonPathFilterExpressionValue.ValueTypeValue.Nothing) {
            return false
        }

        return evaluateComparisonUnpackedSmallerThan(
            firstValue,
            secondValue,
        )
    }

    private fun evaluateComparisonUnpackedSmallerThan(
        first: JsonPathFilterExpressionValue,
        second: JsonPathFilterExpressionValue,
    ): Boolean {
        if (first !is JsonPathFilterExpressionValue.ValueTypeValue.JsonValue) {
            return false
        }
        if (second !is JsonPathFilterExpressionValue.ValueTypeValue.JsonValue) {
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

    // primitives
    override fun visitStringLiteral(ctx: JsonPathParser.StringLiteralContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(ctx.toUnescapedString())
                )
            },
        )
    }

    override fun visitNumber(ctx: JsonPathParser.NumberContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(ctx.NUMBER().text.toDouble())
                )
            },
        )
    }

    override fun visitInt(ctx: JsonPathParser.IntContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(ctx.INT().text.toInt())
                )
            },
        )
    }

    override fun visitTrue(ctx: JsonPathParser.TrueContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(true)
                )
            },
        )
    }

    override fun visitFalse(ctx: JsonPathParser.FalseContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonPrimitive(false)
                )
            },
        )
    }

    override fun visitNull(ctx: JsonPathParser.NullContext): AbstractSyntaxTree<out JsonPathExpression> {
        return AbstractSyntaxTree(
            context = ctx,
            value = JsonPathExpression.FilterExpression.ValueExpression {
                JsonPathFilterExpressionValue.ValueTypeValue.JsonValue(
                    JsonNull
                )
            },
        )
    }
}


internal class QueryNodeBuilder(
    private val context: ParserRuleContext,
    private val contextSelectorNode: AbstractSyntaxTree<out JsonPathExpression>,
    private val selectorSegmentTrees: List<AbstractSyntaxTree<out JsonPathExpression>>
) {
    fun build(): AbstractSyntaxTree<out JsonPathExpression> {
        val children = listOf(
            contextSelectorNode
        ) + selectorSegmentTrees

        val childrenValues = children.map { it.value }
        val childrenSelectors =
            childrenValues.filterIsInstance<JsonPathExpression.SelectorExpression>()
        val value = if (childrenValues.size != childrenSelectors.size) {
            JsonPathExpression.ErrorType
        } else {
            val query = JsonPathSelectorQuery(childrenSelectors.map { it.selector })
            if (query.isSingularQuery) {
                JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression.SingularQueryExpression(
                    query
                )
            } else {
                JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression.NonSingularQueryExpression(
                    query
                )
            }
        }

        return AbstractSyntaxTree(
            context = context,
            value = value,
            children = children,
        )
    }
}