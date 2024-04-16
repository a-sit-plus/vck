package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathLexer
import at.asitplus.parser.generated.JSONPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

/*
A JSONPath implementation MUST raise an error for any query that is
not well-formed and valid.  The well-formedness and the validity of
JSONPath queries are independent of the JSON value the query is
applied to.  No further errors relating to the well-formedness and
the validity of a JSONPath query can be raised during application of
the query to a value.  This clearly separates well-formedness/
validity errors in the query from mismatches that may actually stem
from flaws in the data.

This is currently not the case, an error may only be caught when trying to apply the selectors.
 */
// TODO: Refactor in a way that function extensions can be added by the users of this library
class JSONPathToJSONPathSelectorListCompiler(
    val functionExtensionManager: JSONPathFunctionExtensionManager,
    val errorHandler: JSONPathErrorHandler,
) {
    fun compile(jsonPath: String): List<JSONPathSelector> {
        val lexer = JSONPathLexer(CharStreams.fromString(jsonPath))
        val commonTokenStream = CommonTokenStream(lexer)
        val parser = JSONPathParser(commonTokenStream)

        return JSONPathSelectorEvaluator(
            functionExtensionManager = functionExtensionManager,
            errorHandler = errorHandler,
        ).visit(parser.jsonpath_query()) ?: listOf()
    }
}

private class JSONPathSelectorEvaluator(
    val functionExtensionManager: JSONPathFunctionExtensionManager,
    val errorHandler: JSONPathErrorHandler,
) : JSONPathBaseVisitor<List<JSONPathSelector>>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
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
        return listOf(
            JSONPathSelector.UnionSelector(
                selectors = ctx.selector().flatMap {
                    visitSelector(it)
                }
            )
        )
    }

    override fun visitName_selector(ctx: JSONPathParser.Name_selectorContext): List<JSONPathSelector> {
        val memberName = ctx.string_literal().toUnescapedString()

        return listOf(
            JSONPathSelector.MemberSelector(memberName)
        )
    }

    override fun visitSlice_selector(ctx: JSONPathParser.Slice_selectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.SliceSelector(
                startInclusive = ctx.start()?.int_1()?.text?.toInt(),
                endExclusive = ctx.end()?.int_1()?.text?.toInt(),
                step = ctx.step()?.int_1()?.text?.toInt(),
            )
        )
    }

    override fun visitIndex_selector(ctx: JSONPathParser.Index_selectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.IndexSelector(ctx.text.toInt())
        )
    }

    override fun visitFilter_selector(ctx: JSONPathParser.Filter_selectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.FilterSelector(
                ctx = ctx.logical_expr(),
                functionExtensionManager = functionExtensionManager,
                errorHandler = errorHandler,
            )
        )
    }

    override fun visitMember_name_shorthand(ctx: JSONPathParser.Member_name_shorthandContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.MemberSelector(ctx.text)
        )
    }

    override fun visitWildcardSelector(ctx: JSONPathParser.WildcardSelectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.WildCardSelector()
        )
    }
}