// Generated from C:/Users/stefan.kreiner/Documents/git/com.github/a-sit-plus/jsonpath/jsonpath/build/processedResources/iosArm64/main/grammar/JsonPathParser.g4 by ANTLR 4.13.1
package at.asitplus.jsonpath.generated

import org.antlr.v4.kotlinruntime.tree.ParseTreeListener

/**
 * This interface defines a complete listener for a parse tree produced by [JsonPathParser].
 */
public interface JsonPathParserListener : ParseTreeListener {
    /**
     * Enter a parse tree produced by [JsonPathParser.jsonpath_query].
     *
     * @param ctx The parse tree
     */
    public fun enterJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.jsonpath_query].
     *
     * @param ctx The parse tree
     */
    public fun exitJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.segments].
     *
     * @param ctx The parse tree
     */
    public fun enterSegments(ctx: JsonPathParser.SegmentsContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.segments].
     *
     * @param ctx The parse tree
     */
    public fun exitSegments(ctx: JsonPathParser.SegmentsContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.segment].
     *
     * @param ctx The parse tree
     */
    public fun enterSegment(ctx: JsonPathParser.SegmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.segment].
     *
     * @param ctx The parse tree
     */
    public fun exitSegment(ctx: JsonPathParser.SegmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.shorthand_segment].
     *
     * @param ctx The parse tree
     */
    public fun enterShorthand_segment(ctx: JsonPathParser.Shorthand_segmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.shorthand_segment].
     *
     * @param ctx The parse tree
     */
    public fun exitShorthand_segment(ctx: JsonPathParser.Shorthand_segmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.descendant_segment].
     *
     * @param ctx The parse tree
     */
    public fun enterDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.descendant_segment].
     *
     * @param ctx The parse tree
     */
    public fun exitDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.bracketed_selection].
     *
     * @param ctx The parse tree
     */
    public fun enterBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.bracketed_selection].
     *
     * @param ctx The parse tree
     */
    public fun exitBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.selector].
     *
     * @param ctx The parse tree
     */
    public fun enterSelector(ctx: JsonPathParser.SelectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.selector].
     *
     * @param ctx The parse tree
     */
    public fun exitSelector(ctx: JsonPathParser.SelectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.name_selector].
     *
     * @param ctx The parse tree
     */
    public fun enterName_selector(ctx: JsonPathParser.Name_selectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.name_selector].
     *
     * @param ctx The parse tree
     */
    public fun exitName_selector(ctx: JsonPathParser.Name_selectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.index_selector].
     *
     * @param ctx The parse tree
     */
    public fun enterIndex_selector(ctx: JsonPathParser.Index_selectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.index_selector].
     *
     * @param ctx The parse tree
     */
    public fun exitIndex_selector(ctx: JsonPathParser.Index_selectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.slice_selector].
     *
     * @param ctx The parse tree
     */
    public fun enterSlice_selector(ctx: JsonPathParser.Slice_selectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.slice_selector].
     *
     * @param ctx The parse tree
     */
    public fun exitSlice_selector(ctx: JsonPathParser.Slice_selectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.start].
     *
     * @param ctx The parse tree
     */
    public fun enterStart(ctx: JsonPathParser.StartContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.start].
     *
     * @param ctx The parse tree
     */
    public fun exitStart(ctx: JsonPathParser.StartContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.end].
     *
     * @param ctx The parse tree
     */
    public fun enterEnd(ctx: JsonPathParser.EndContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.end].
     *
     * @param ctx The parse tree
     */
    public fun exitEnd(ctx: JsonPathParser.EndContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.step].
     *
     * @param ctx The parse tree
     */
    public fun enterStep(ctx: JsonPathParser.StepContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.step].
     *
     * @param ctx The parse tree
     */
    public fun exitStep(ctx: JsonPathParser.StepContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.filter_query].
     *
     * @param ctx The parse tree
     */
    public fun enterFilter_query(ctx: JsonPathParser.Filter_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.filter_query].
     *
     * @param ctx The parse tree
     */
    public fun exitFilter_query(ctx: JsonPathParser.Filter_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.rel_query].
     *
     * @param ctx The parse tree
     */
    public fun enterRel_query(ctx: JsonPathParser.Rel_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.rel_query].
     *
     * @param ctx The parse tree
     */
    public fun exitRel_query(ctx: JsonPathParser.Rel_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.singular_query].
     *
     * @param ctx The parse tree
     */
    public fun enterSingular_query(ctx: JsonPathParser.Singular_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.singular_query].
     *
     * @param ctx The parse tree
     */
    public fun exitSingular_query(ctx: JsonPathParser.Singular_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.rel_singular_query].
     *
     * @param ctx The parse tree
     */
    public fun enterRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.rel_singular_query].
     *
     * @param ctx The parse tree
     */
    public fun exitRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.abs_singular_query].
     *
     * @param ctx The parse tree
     */
    public fun enterAbs_singular_query(ctx: JsonPathParser.Abs_singular_queryContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.abs_singular_query].
     *
     * @param ctx The parse tree
     */
    public fun exitAbs_singular_query(ctx: JsonPathParser.Abs_singular_queryContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.singular_query_segments].
     *
     * @param ctx The parse tree
     */
    public fun enterSingular_query_segments(ctx: JsonPathParser.Singular_query_segmentsContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.singular_query_segments].
     *
     * @param ctx The parse tree
     */
    public fun exitSingular_query_segments(ctx: JsonPathParser.Singular_query_segmentsContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.singular_query_segment].
     *
     * @param ctx The parse tree
     */
    public fun enterSingular_query_segment(ctx: JsonPathParser.Singular_query_segmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.singular_query_segment].
     *
     * @param ctx The parse tree
     */
    public fun exitSingular_query_segment(ctx: JsonPathParser.Singular_query_segmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.name_segment].
     *
     * @param ctx The parse tree
     */
    public fun enterName_segment(ctx: JsonPathParser.Name_segmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.name_segment].
     *
     * @param ctx The parse tree
     */
    public fun exitName_segment(ctx: JsonPathParser.Name_segmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.index_segment].
     *
     * @param ctx The parse tree
     */
    public fun enterIndex_segment(ctx: JsonPathParser.Index_segmentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.index_segment].
     *
     * @param ctx The parse tree
     */
    public fun exitIndex_segment(ctx: JsonPathParser.Index_segmentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.filter_selector].
     *
     * @param ctx The parse tree
     */
    public fun enterFilter_selector(ctx: JsonPathParser.Filter_selectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.filter_selector].
     *
     * @param ctx The parse tree
     */
    public fun exitFilter_selector(ctx: JsonPathParser.Filter_selectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.logical_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterLogical_expr(ctx: JsonPathParser.Logical_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.logical_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitLogical_expr(ctx: JsonPathParser.Logical_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.logical_or_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.logical_or_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.logical_and_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.logical_and_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.basic_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterBasic_expr(ctx: JsonPathParser.Basic_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.basic_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitBasic_expr(ctx: JsonPathParser.Basic_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.paren_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterParen_expr(ctx: JsonPathParser.Paren_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.paren_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitParen_expr(ctx: JsonPathParser.Paren_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.test_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterTest_expr(ctx: JsonPathParser.Test_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.test_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitTest_expr(ctx: JsonPathParser.Test_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.comparison_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterComparison_expr(ctx: JsonPathParser.Comparison_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.comparison_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitComparison_expr(ctx: JsonPathParser.Comparison_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.firstComparable].
     *
     * @param ctx The parse tree
     */
    public fun enterFirstComparable(ctx: JsonPathParser.FirstComparableContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.firstComparable].
     *
     * @param ctx The parse tree
     */
    public fun exitFirstComparable(ctx: JsonPathParser.FirstComparableContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.secondComparable].
     *
     * @param ctx The parse tree
     */
    public fun enterSecondComparable(ctx: JsonPathParser.SecondComparableContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.secondComparable].
     *
     * @param ctx The parse tree
     */
    public fun exitSecondComparable(ctx: JsonPathParser.SecondComparableContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.literal].
     *
     * @param ctx The parse tree
     */
    public fun enterLiteral(ctx: JsonPathParser.LiteralContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.literal].
     *
     * @param ctx The parse tree
     */
    public fun exitLiteral(ctx: JsonPathParser.LiteralContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.comparable].
     *
     * @param ctx The parse tree
     */
    public fun enterComparable(ctx: JsonPathParser.ComparableContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.comparable].
     *
     * @param ctx The parse tree
     */
    public fun exitComparable(ctx: JsonPathParser.ComparableContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.function_expr].
     *
     * @param ctx The parse tree
     */
    public fun enterFunction_expr(ctx: JsonPathParser.Function_exprContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.function_expr].
     *
     * @param ctx The parse tree
     */
    public fun exitFunction_expr(ctx: JsonPathParser.Function_exprContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.function_argument].
     *
     * @param ctx The parse tree
     */
    public fun enterFunction_argument(ctx: JsonPathParser.Function_argumentContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.function_argument].
     *
     * @param ctx The parse tree
     */
    public fun exitFunction_argument(ctx: JsonPathParser.Function_argumentContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.rootIdentifier].
     *
     * @param ctx The parse tree
     */
    public fun enterRootIdentifier(ctx: JsonPathParser.RootIdentifierContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.rootIdentifier].
     *
     * @param ctx The parse tree
     */
    public fun exitRootIdentifier(ctx: JsonPathParser.RootIdentifierContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.currentNodeIdentifier].
     *
     * @param ctx The parse tree
     */
    public fun enterCurrentNodeIdentifier(ctx: JsonPathParser.CurrentNodeIdentifierContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.currentNodeIdentifier].
     *
     * @param ctx The parse tree
     */
    public fun exitCurrentNodeIdentifier(ctx: JsonPathParser.CurrentNodeIdentifierContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.ws].
     *
     * @param ctx The parse tree
     */
    public fun enterWs(ctx: JsonPathParser.WsContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.ws].
     *
     * @param ctx The parse tree
     */
    public fun exitWs(ctx: JsonPathParser.WsContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.wildcardSelector].
     *
     * @param ctx The parse tree
     */
    public fun enterWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.wildcardSelector].
     *
     * @param ctx The parse tree
     */
    public fun exitWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.memberNameShorthand].
     *
     * @param ctx The parse tree
     */
    public fun enterMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.memberNameShorthand].
     *
     * @param ctx The parse tree
     */
    public fun exitMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.stringLiteral].
     *
     * @param ctx The parse tree
     */
    public fun enterStringLiteral(ctx: JsonPathParser.StringLiteralContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.stringLiteral].
     *
     * @param ctx The parse tree
     */
    public fun exitStringLiteral(ctx: JsonPathParser.StringLiteralContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.number].
     *
     * @param ctx The parse tree
     */
    public fun enterNumber(ctx: JsonPathParser.NumberContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.number].
     *
     * @param ctx The parse tree
     */
    public fun exitNumber(ctx: JsonPathParser.NumberContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.int].
     *
     * @param ctx The parse tree
     */
    public fun enterInt(ctx: JsonPathParser.IntContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.int].
     *
     * @param ctx The parse tree
     */
    public fun exitInt(ctx: JsonPathParser.IntContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.true].
     *
     * @param ctx The parse tree
     */
    public fun enterTrue(ctx: JsonPathParser.TrueContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.true].
     *
     * @param ctx The parse tree
     */
    public fun exitTrue(ctx: JsonPathParser.TrueContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.false].
     *
     * @param ctx The parse tree
     */
    public fun enterFalse(ctx: JsonPathParser.FalseContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.false].
     *
     * @param ctx The parse tree
     */
    public fun exitFalse(ctx: JsonPathParser.FalseContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.null].
     *
     * @param ctx The parse tree
     */
    public fun enterNull(ctx: JsonPathParser.NullContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.null].
     *
     * @param ctx The parse tree
     */
    public fun exitNull(ctx: JsonPathParser.NullContext)

    /**
     * Enter a parse tree produced by [JsonPathParser.comparisonOp].
     *
     * @param ctx The parse tree
     */
    public fun enterComparisonOp(ctx: JsonPathParser.ComparisonOpContext)

    /**
     * Exit a parse tree produced by [JsonPathParser.comparisonOp].
     *
     * @param ctx The parse tree
     */
    public fun exitComparisonOp(ctx: JsonPathParser.ComparisonOpContext)

}
