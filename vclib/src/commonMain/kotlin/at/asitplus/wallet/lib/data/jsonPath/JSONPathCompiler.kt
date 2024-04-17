package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathLexer
import at.asitplus.parser.generated.JSONPathParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

interface JSONPathCompiler {
    fun compile(jsonPath: String): JSONPathMatcher
}

val jsonPathCompiler by lazy {
    object : JSONPathCompiler {
        override fun compile(jsonPath: String): JSONPathMatcher {
            val lexer = JSONPathLexer(CharStreams.fromString(jsonPath))
            val commonTokenStream = CommonTokenStream(lexer)
            val parser = JSONPathParser(commonTokenStream)

            val selectors = JSONPathSelectorEvaluationVisitor().visit(parser.jsonpath_query()) ?: listOf()

            return SimpleJSONPathMatcher(selectors)
        }
    }
}