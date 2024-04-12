package at.asitplus.wallet.lib.data.JSONPath

import at.asitplus.parser.generated.JSONPathBaseVisitor
import at.asitplus.parser.generated.JSONPathLexer
import at.asitplus.parser.generated.JSONPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

class JSONPathToJSONPathSelectorListCompiler(
    val functionExtensions: Map<String, FunctionExtensionEvaluator> = mapOf(),
) {
    fun compile(jsonPath: String): List<JSONPathSelector>? {
        val lexer = JSONPathLexer(CharStreams.fromString(jsonPath))
        val commonTokenStream = CommonTokenStream(lexer)
        val parser = JSONPathParser(commonTokenStream)

        return JSONPathSelectorListEvaluator(
            functionExtensions = functionExtensions,
        ).visit(parser.jsonpathQuery())
    }
}

private class JSONPathSelectorListEvaluator(
    val functionExtensions: Map<String, FunctionExtensionEvaluator>,
) : JSONPathBaseVisitor<List<JSONPathSelector>>() {
    // source: https://datatracker.ietf.org/doc/rfc9535/ from 2024-02-21

    override fun aggregateResult(
        aggregate: List<JSONPathSelector>?,
        nextResult: List<JSONPathSelector>
    ): List<JSONPathSelector> = (aggregate ?: listOf()) + nextResult

    override fun visitRootIdentifier(ctx: JSONPathParser.RootIdentifierContext): List<JSONPathSelector> {
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
        return listOf(
            JSONPathSelector.WildCardSelector()
        )
    }
}

class InvalidJSONPathException(jsonPath: String) : Exception(jsonPath)