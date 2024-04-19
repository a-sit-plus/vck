package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathLexer
import at.asitplus.parser.generated.JsonPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

interface JsonPathCompiler {
    fun compile(jsonPath: String): JsonPathQuery

    fun setErrorListener(errorListener: JsonPathCompilerErrorListener?)

    fun getErrorListener(): JsonPathCompilerErrorListener?

    fun setFunctionExtensionManager(functionExtensionManager: JsonPathFunctionExtensionManager?)

    fun getFunctionExtensionManager(): JsonPathFunctionExtensionManager?
}

class BaseJsonPathCompiler(
    private var errorListener: JsonPathCompilerErrorListener? = null,
    private var functionExtensionManager: JsonPathFunctionExtensionManager? = null,
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

        val selectors = JsonPathSelectorEvaluationVisitor(
            compiler = this,
        ).visit(parser.jsonpath_query()) ?: listOf()

        return SimpleJsonPathQuery(selectors)
    }

    override fun setErrorListener(errorListener: JsonPathCompilerErrorListener?) {
        this.errorListener = errorListener
    }

    override fun getErrorListener(): JsonPathCompilerErrorListener? {
        return errorListener
    }

    override fun setFunctionExtensionManager(functionExtensionManager: JsonPathFunctionExtensionManager?) {
        this.functionExtensionManager = functionExtensionManager
    }

    override fun getFunctionExtensionManager(): JsonPathFunctionExtensionManager? {
        return this.functionExtensionManager
    }
}

val defaultJsonPathCompiler by lazy {
    BaseJsonPathCompiler(
        errorListener = napierJsonPathCompilerErrorListener,
        functionExtensionManager = defaultFunctionExtensionManager,
    )
}