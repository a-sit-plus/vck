// Generated from C:/Users/stefan.kreiner/Documents/git/com.github/a-sit-plus/jsonpath/jsonpath/build/processedResources/iosArm64/main/grammar/JsonPathParser.g4 by ANTLR 4.13.1
package at.asitplus.jsonpath.generated

import org.antlr.v4.kotlinruntime.tree.AbstractParseTreeVisitor

/**
 * This class provides an empty implementation of [JsonPathParserVisitor],
 * which can be extended to create a visitor which only needs to handle a subset
 * of the available methods.
 *
 * @param T The return type of the visit operation.
 *   Use [Unit] for operations with no return type
 */
public open class JsonPathParserBaseVisitor<T> : AbstractParseTreeVisitor<T>(),
    JsonPathParserVisitor<T> {
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitJsonpath_query(ctx: JsonPathParser.Jsonpath_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSegments(ctx: JsonPathParser.SegmentsContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSegment(ctx: JsonPathParser.SegmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitShorthand_segment(ctx: JsonPathParser.Shorthand_segmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSelector(ctx: JsonPathParser.SelectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitName_selector(ctx: JsonPathParser.Name_selectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitIndex_selector(ctx: JsonPathParser.Index_selectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSlice_selector(ctx: JsonPathParser.Slice_selectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitStart(ctx: JsonPathParser.StartContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitEnd(ctx: JsonPathParser.EndContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitStep(ctx: JsonPathParser.StepContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFilter_query(ctx: JsonPathParser.Filter_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitRel_query(ctx: JsonPathParser.Rel_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSingular_query(ctx: JsonPathParser.Singular_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitRel_singular_query(ctx: JsonPathParser.Rel_singular_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitAbs_singular_query(ctx: JsonPathParser.Abs_singular_queryContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSingular_query_segments(ctx: JsonPathParser.Singular_query_segmentsContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSingular_query_segment(ctx: JsonPathParser.Singular_query_segmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitName_segment(ctx: JsonPathParser.Name_segmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitIndex_segment(ctx: JsonPathParser.Index_segmentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFilter_selector(ctx: JsonPathParser.Filter_selectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitLogical_or_expr(ctx: JsonPathParser.Logical_or_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitLogical_and_expr(ctx: JsonPathParser.Logical_and_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitBasic_expr(ctx: JsonPathParser.Basic_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitParen_expr(ctx: JsonPathParser.Paren_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitTest_expr(ctx: JsonPathParser.Test_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitComparison_expr(ctx: JsonPathParser.Comparison_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFirstComparable(ctx: JsonPathParser.FirstComparableContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitSecondComparable(ctx: JsonPathParser.SecondComparableContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitLiteral(ctx: JsonPathParser.LiteralContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitComparable(ctx: JsonPathParser.ComparableContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFunction_expr(ctx: JsonPathParser.Function_exprContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFunction_argument(ctx: JsonPathParser.Function_argumentContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitRootIdentifier(ctx: JsonPathParser.RootIdentifierContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitCurrentNodeIdentifier(ctx: JsonPathParser.CurrentNodeIdentifierContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitWs(ctx: JsonPathParser.WsContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitStringLiteral(ctx: JsonPathParser.StringLiteralContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitNumber(ctx: JsonPathParser.NumberContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitInt(ctx: JsonPathParser.IntContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitTrue(ctx: JsonPathParser.TrueContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitFalse(ctx: JsonPathParser.FalseContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitNull(ctx: JsonPathParser.NullContext): T {
        return this.visitChildren(ctx)!!
    }
    /**
     * The default implementation returns the result of calling [visitChildren] on [ctx].
     */
    override fun visitComparisonOp(ctx: JsonPathParser.ComparisonOpContext): T {
        return this.visitChildren(ctx)!!
    }
}
