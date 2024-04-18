package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathLexer
import at.asitplus.parser.generated.JSONPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

interface JSONPathCompiler {
    fun compile(jsonPath: String): JSONPathQuery

    fun setErrorHandler(errorHandler: JSONPathErrorHandler?)

    fun getErrorHandler(): JSONPathErrorHandler?

    fun setFunctionExtensionManager(functionExtensionManager: JSONPathFunctionExtensionManager?)

    fun getFunctionExtensionManager(): JSONPathFunctionExtensionManager?
}

val jsonPathCompiler by lazy {
    object : JSONPathCompiler {
        private var errorHandler: JSONPathErrorHandler? = napierJSONPathErrorHandler
        private var functionExtensionManager: JSONPathFunctionExtensionManager? = defaultFunctionExtensionManager

        override fun compile(jsonPath: String): JSONPathQuery {
            val lexer = JSONPathLexer(CharStreams.fromString(jsonPath))
            val commonTokenStream = CommonTokenStream(lexer)
            val parser = JSONPathParser(commonTokenStream)

            val selectors = JSONPathSelectorEvaluationVisitor(
                compiler = this,
            ).visit(parser.jsonpath_query()) ?: listOf()

            return SimpleJSONPathQuery(selectors)
        }

        override fun setErrorHandler(errorHandler: JSONPathErrorHandler?) {
            this.errorHandler = errorHandler
        }

        override fun getErrorHandler(): JSONPathErrorHandler? {
            return errorHandler
        }

        override fun setFunctionExtensionManager(functionExtensionManager: JSONPathFunctionExtensionManager?) {
            this.functionExtensionManager = functionExtensionManager
        }

        override fun getFunctionExtensionManager(): JSONPathFunctionExtensionManager? {
            return this.functionExtensionManager
        }
    }
}