package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathLexer
import at.asitplus.parser.generated.JsonPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

class AntlrJsonPathCompiler(
    private var functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
    private var errorListener: AntlrJsonPathCompilerErrorListener? = null,
) : JsonPathCompiler {
    override fun compile(jsonPath: String): JsonPathQuery {
        val lexer = JsonPathLexer(CharStreams.fromString(jsonPath))
        errorListener?.let {
            lexer.addErrorListener(it)
        }
        val commonTokenStream = CommonTokenStream(lexer)
        val parser = JsonPathParser(commonTokenStream)
        errorListener?.let {
            parser.addErrorListener(it)
        }

        val selectors = AntlrJsonPathSelectorEvaluationVisitor(
            compiler = this,
            errorListener = errorListener,
            functionExtensionRetriever = functionExtensionRetriever,
        ).visit(parser.jsonpath_query()) ?: listOf()

        return JsonPathQuery(selectors)
    }

    fun setErrorListener(errorListener: AntlrJsonPathCompilerErrorListener?) {
        this.errorListener = errorListener
    }

    fun getErrorListener(): AntlrJsonPathCompilerErrorListener? {
        return errorListener
    }
}