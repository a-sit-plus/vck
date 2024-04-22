package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser
import at.asitplus.parser.generated.JsonPathParserBaseVisitor
import kotlinx.serialization.json.JsonElement

class AntlrJsonPathSelectorEvaluationVisitor(
    private val compiler: JsonPathCompiler,
    private val errorListener: AntlrJsonPathCompilerErrorListener?,
    private val functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
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

    override fun visitLogical_expr(ctx: JsonPathParser.Logical_exprContext): List<JsonPathSelector> {
        val hasValidTypes = AntlrJsonPathTypeCheckerVisitor(
            compiler = compiler,
            errorListener = errorListener,
            functionExtensionRetriever = functionExtensionRetriever,
        ).visitLogical_expr(ctx)
        if (hasValidTypes == false) {
            throw JsonPathTypeCheckerException("See the output of the error handler for more details.")
        }
        return listOf(
            JsonPathSelector.FilterSelector(
                filterPredicate = object : FilterPredicate {
                    override fun invoke(
                        currentNode: JsonElement,
                        rootNode: JsonElement
                    ): Boolean {
                        return AntlrJsonPathExpressionEvaluationVisitor(
                            rootNode = rootNode,
                            currentNode = currentNode,
                            compiler = compiler,
                            functionExtensionRetriever = functionExtensionRetriever,
                        ).visitLogical_expr(
                            ctx
                        ).isTrue
                    }
                }
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