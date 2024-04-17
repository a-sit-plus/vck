package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser
import at.asitplus.parser.generated.JSONPathParserBaseVisitor

class JSONPathSelectorEvaluationVisitor : JSONPathParserBaseVisitor<List<JSONPathSelector>>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21

    override fun defaultResult(): List<JSONPathSelector> {
        return listOf()
    }

    override fun aggregateResult(
        aggregate: List<JSONPathSelector>?,
        nextResult: List<JSONPathSelector>
    ): List<JSONPathSelector> = (aggregate ?: listOf()) + nextResult

    override fun visitRootSegment(ctx: JSONPathParser.RootSegmentContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.RootSelector()
        )
    }

    override fun visitDescendant_segment(ctx: JSONPathParser.Descendant_segmentContext): List<JSONPathSelector> {
        return listOfNotNull(
            JSONPathSelector.DescendantSelector(),
        ) + (this.visitChildren(ctx) ?: listOf())
    }

    override fun visitBracketed_selection(ctx: JSONPathParser.Bracketed_selectionContext): List<JSONPathSelector> {
        println("visitBracketed_selection")
        return listOf(
            JSONPathSelector.UnionSelector(
                selectors = ctx.selector().flatMap {
                    visitSelector(it)
                }
            )
        )
    }

    override fun visitName_selector(ctx: JSONPathParser.Name_selectorContext): List<JSONPathSelector> {
        val memberName = ctx.stringLiteral().toUnescapedString()

        return listOf(
            JSONPathSelector.MemberSelector(memberName)
        )
    }

    override fun visitSlice_selector(ctx: JSONPathParser.Slice_selectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.SliceSelector(
                startInclusive = ctx.start()?.text?.toInt(),
                endExclusive = ctx.end()?.text?.toInt(),
                step = ctx.step()?.text?.toInt(),
            )
        )
    }

    override fun visitIndex_selector(ctx: JSONPathParser.Index_selectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.IndexSelector(ctx.text.toInt())
        )
    }

    override fun visitMemberNameShorthandSelector(ctx: JSONPathParser.MemberNameShorthandSelectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.MemberSelector(ctx.text)
        )
    }

    override fun visitWildcardSelector(ctx: JSONPathParser.WildcardSelectorContext): List<JSONPathSelector> {
        println("WildcardSelector")
        return listOf(
            JSONPathSelector.WildCardSelector()
        )
    }
}