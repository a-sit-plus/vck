package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor

class JsonPathSelectorEvaluationVisitor(
    private val compiler: JsonPathCompiler,
) : JsonPathParserBaseVisitor<List<JsonPathSelector>>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
    override fun defaultResult(): List<JsonPathSelector> {
        return listOf()
    }

    override fun aggregateResult(
        aggregate: List<JsonPathSelector>?,
        nextResult: List<JsonPathSelector>
    ): List<JsonPathSelector> = (aggregate ?: listOf()) + nextResult

    override fun visitRootIdentifier(ctx: JsonPathParser.RootIdentifierContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.RootSelector
        )
    }

    override fun visitDescendant_segment(ctx: JsonPathParser.Descendant_segmentContext): List<JsonPathSelector> {
        return listOfNotNull(
            JsonPathSelector.DescendantSelector,
        ) + (this.visitChildren(ctx) ?: listOf())
    }

    override fun visitBracketed_selection(ctx: JsonPathParser.Bracketed_selectionContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.UnionSelector(
                selectors = ctx.selector().flatMap {
                    visitSelector(it)
                }
            )
        )
    }

    override fun visitName_selector(ctx: JsonPathParser.Name_selectorContext): List<JsonPathSelector> {
        val memberName = ctx.stringLiteral().toUnescapedString()

        return listOf(
            JsonPathSelector.MemberSelector(memberName)
        )
    }

    override fun visitSlice_selector(ctx: JsonPathParser.Slice_selectorContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.SliceSelector(
                startInclusive = ctx.start()?.text?.toInt(),
                endExclusive = ctx.end()?.text?.toInt(),
                step = ctx.step()?.text?.toInt(),
            )
        )
    }

    override fun visitIndex_selector(ctx: JsonPathParser.Index_selectorContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.IndexSelector(ctx.text.toInt())
        )
    }

    override fun visitFilter_selector(ctx: JsonPathParser.Filter_selectorContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.FilterSelector(
                ctx = ctx.logical_expr(),
                compiler = compiler,
            )
        )
    }

    override fun visitMemberNameShorthand(ctx: JsonPathParser.MemberNameShorthandContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.MemberSelector(ctx.text)
        )
    }

    override fun visitWildcardSelector(ctx: JsonPathParser.WildcardSelectorContext): List<JsonPathSelector> {
        return listOf(
            JsonPathSelector.WildCardSelector
        )
    }
}