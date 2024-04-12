package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathLexer
import at.asitplus.parser.generated.JSONPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream
import org.antlr.v4.kotlinruntime.tree.TerminalNode

/* TODO:
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
    val functionExtensions: Map<String, FunctionExtensionEvaluator> =
        JSONPathToJSONPathSelectorListCompilerDefaults.functionExtensions,
) {
    fun compile(jsonPath: String): List<JSONPathSelector>? {
        val lexer = JSONPathLexer(CharStreams.fromString(jsonPath))
        val commonTokenStream = CommonTokenStream(lexer)
        val parser = JSONPathParser(commonTokenStream)

        return JSONPathSelectorEvaluator(
            functionExtensions = functionExtensions,
        ).visit(parser.jsonpathQuery())
    }
}

class JSONPathToJSONPathSelectorListCompilerDefaults {
    companion object {
        val functionExtensions: Map<String, FunctionExtensionEvaluator> = listOf(
            LengthFunctionExtension,
            CountFunctionExtension,
            MatchFunctionExtension,
            SearchFunctionExtension,
            ValueFunctionExtension,
        ).map {
            it.name to it.evaluator
        }.toMap()
    }
}

private class JSONPathSelectorEvaluator(
    val functionExtensions: Map<String, FunctionExtensionEvaluator>,
) : JSONPathBaseVisitor<List<JSONPathSelector>>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21
    override fun visitTerminal(node: TerminalNode): List<JSONPathSelector> {
        return listOf()
    }

    override fun defaultResult(): List<JSONPathSelector> {
        return listOf()
    }

    override fun aggregateResult(
        aggregate: List<JSONPathSelector>?,
        nextResult: List<JSONPathSelector>
    ): List<JSONPathSelector> = (aggregate ?: listOf()) + nextResult

    override fun visitJsonpathQuery(ctx: JSONPathParser.JsonpathQueryContext): List<JSONPathSelector> {
        println("visitJsonpathQuery: ${ctx.text}")
        return super.visitJsonpathQuery(ctx)
    }
    override fun visitSegments(ctx: JSONPathParser.SegmentsContext): List<JSONPathSelector> {
        println("segments: ${ctx.text}")
        return super.visitSegments(ctx)
    }

    override fun visitSegment(ctx: JSONPathParser.SegmentContext): List<JSONPathSelector> {
        println("segment: ${ctx.text}")
        return super.visitSegment(ctx)
    }

    override fun visitChildSegment(ctx: JSONPathParser.ChildSegmentContext): List<JSONPathSelector> {
        println("visitChildSegment: ${ctx.text}: ${ctx.children}: ${ctx.wildcardSelector()}, ${ctx.bracketedSelection()}, ${ctx.memberNameShorthand()}")
        return ctx.wildcardSelector()?.let { visitWildcardSelector(it) }
            ?: ctx.bracketedSelection()?.let { visitBracketedSelection(it) }
            ?: ctx.memberNameShorthand()!!.let { visitMemberNameShorthand(it) }
    }
    override fun visitRootIdentifier(ctx: JSONPathParser.RootIdentifierContext): List<JSONPathSelector> {
        println("root identifier: ${ctx.text}")
        return listOf(
            JSONPathSelector.RootSelector()
        )
    }

    override fun visitDescendantSegment(ctx: JSONPathParser.DescendantSegmentContext): List<JSONPathSelector> {
        return listOfNotNull(
            JSONPathSelector.DescendantSelector(),
        ) + (this.visitChildren(ctx) ?: listOf())
    }

    override fun visitBracketedSelection(ctx: JSONPathParser.BracketedSelectionContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.UnionSelector(
                selectors = ctx.selector().flatMap {
                    visitSelector(it)
                }
            ))
    }

    override fun visitNameSelector(ctx: JSONPathParser.NameSelectorContext): List<JSONPathSelector> {
        val memberName = ctx.stringLiteral().toUnescapedString()

        return listOf(
            JSONPathSelector.MemberSelector(memberName)
        )
    }

    override fun visitSliceSelector(ctx: JSONPathParser.SliceSelectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.SliceSelector(
                startInclusive = ctx.start()?.int()?.text?.toInt(),
                endExclusive = ctx.end()?.int()?.text?.toInt(),
                step = ctx.step()?.int()?.text?.toInt(),
            )
        )
    }

    override fun visitIndexSelector(ctx: JSONPathParser.IndexSelectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.IndexSelector(ctx.text.toInt())
        )
    }

    override fun visitFilterSelector(ctx: JSONPathParser.FilterSelectorContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.FilterSelector(
                ctx = ctx.logicalExpr(),
                functionExtensions = functionExtensions,
            )
        )
    }

    override fun visitMemberNameShorthand(ctx: JSONPathParser.MemberNameShorthandContext): List<JSONPathSelector> {
        return listOf(
            JSONPathSelector.MemberSelector(ctx.text)
        )
    }

    override fun visitWildcardSelector(ctx: JSONPathParser.WildcardSelectorContext): List<JSONPathSelector> {
        println("visitWildcardSelector: ${ctx.text}")
        return listOf(
            JSONPathSelector.WildCardSelector()
        )
    }
}

class InvalidJSONPathException(jsonPath: String) : Exception(jsonPath)