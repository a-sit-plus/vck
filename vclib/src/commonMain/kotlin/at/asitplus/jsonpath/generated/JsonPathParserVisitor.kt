// Generated from C:/Users/stefan.kreiner/Documents/git/com.github/a-sit-plus/jsonpath/jsonpath/build/processedResources/iosArm64/main/grammar/JsonPathParser.g4 by ANTLR 4.13.1
package at.asitplus.jsonpath.generated

import org.antlr.v4.kotlinruntime.tree.ParseTreeVisitor

/**
 * This interface defines a complete generic visitor for a parse tree produced by [JsonPathParser].
 *
 * @param T The return type of the visit operation.
 *   Use [Unit] for operations with no return type
 */
public interface JsonPathParserVisitor<T> : ParseTreeVisitor<T> {
    /**
     * Visit a parse tree produced by [JsonPathParser.jsonpath_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.segments].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSegments(ctx: JsonPathParser.SegmentsContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSegment(ctx: JsonPathParser.SegmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.shorthand_segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitShorthand_segment(ctx: JsonPathParser.Shorthand_segmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.descendant_segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.bracketed_selection].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.selector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSelector(ctx: JsonPathParser.SelectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.name_selector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitName_selector(ctx: JsonPathParser.Name_selectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.index_selector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitIndex_selector(ctx: JsonPathParser.Index_selectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.slice_selector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSlice_selector(ctx: JsonPathParser.Slice_selectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.start].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitStart(ctx: JsonPathParser.StartContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.end].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitEnd(ctx: JsonPathParser.EndContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.step].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitStep(ctx: JsonPathParser.StepContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.filter_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFilter_query(ctx: JsonPathParser.Filter_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.rel_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitRel_query(ctx: JsonPathParser.Rel_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.singular_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSingular_query(ctx: JsonPathParser.Singular_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.rel_singular_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.abs_singular_query].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitAbs_singular_query(ctx: JsonPathParser.Abs_singular_queryContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.singular_query_segments].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSingular_query_segments(ctx: JsonPathParser.Singular_query_segmentsContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.singular_query_segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSingular_query_segment(ctx: JsonPathParser.Singular_query_segmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.name_segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitName_segment(ctx: JsonPathParser.Name_segmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.index_segment].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitIndex_segment(ctx: JsonPathParser.Index_segmentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.filter_selector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFilter_selector(ctx: JsonPathParser.Filter_selectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.logical_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.logical_or_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.logical_and_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.basic_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitBasic_expr(ctx: JsonPathParser.Basic_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.paren_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitParen_expr(ctx: JsonPathParser.Paren_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.test_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.comparison_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.firstComparable].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFirstComparable(ctx: JsonPathParser.FirstComparableContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.secondComparable].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitSecondComparable(ctx: JsonPathParser.SecondComparableContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.literal].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitLiteral(ctx: JsonPathParser.LiteralContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.comparable].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitComparable(ctx: JsonPathParser.ComparableContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.function_expr].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.function_argument].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFunction_argument(ctx: JsonPathParser.Function_argumentContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.rootIdentifier].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitRootIdentifier(ctx: JsonPathParser.RootIdentifierContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.currentNodeIdentifier].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitCurrentNodeIdentifier(ctx: JsonPathParser.CurrentNodeIdentifierContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.ws].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitWs(ctx: JsonPathParser.WsContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.wildcardSelector].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.memberNameShorthand].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.stringLiteral].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitStringLiteral(ctx: JsonPathParser.StringLiteralContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.number].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitNumber(ctx: JsonPathParser.NumberContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.int].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitInt(ctx: JsonPathParser.IntContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.true].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitTrue(ctx: JsonPathParser.TrueContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.false].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitFalse(ctx: JsonPathParser.FalseContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.null].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitNull(ctx: JsonPathParser.NullContext): T

    /**
     * Visit a parse tree produced by [JsonPathParser.comparisonOp].
     *
     * @param ctx The parse tree
     * @return The visitor result
     */
    public fun visitComparisonOp(ctx: JsonPathParser.ComparisonOpContext): T

}
