package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.JsonPathCompiler
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import at.asitplus.jsonpath.core.JsonPathQuery
import at.asitplus.jsonpath.core.NodeList
import at.asitplus.jsonpath.generated.JsonPathLexer
import at.asitplus.jsonpath.generated.JsonPathParser
import kotlinx.serialization.json.JsonElement
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream
import org.antlr.v4.kotlinruntime.ListTokenSource

class AntlrJsonPathCompiler(
    private var functionExtensionRetriever: (String) -> JsonPathFunctionExtension<*>?,
    private var errorListener: AntlrJsonPathCompilerErrorListener? = null,
) : JsonPathCompiler {
    override fun compile(jsonPath: String): JsonPathQuery {
        val lexerErrorDetector = AntlrSyntaxErrorDetector()
        val tokens = JsonPathLexer(CharStreams.fromString(jsonPath)).apply {
            addErrorListener(lexerErrorDetector)
            errorListener?.let {
                addErrorListener(it)
            }
        }.allTokens

        if(lexerErrorDetector.isError) {
            throw JsonPathLexerException()
        }

        val parserErrorDetector = AntlrSyntaxErrorDetector()
        val commonTokenStream = CommonTokenStream(ListTokenSource(tokens))
        val jsonPathQueryContext = JsonPathParser(commonTokenStream).apply {
            addErrorListener(parserErrorDetector)
            errorListener?.let {
                addErrorListener(it)
            }
        }.jsonpath_query()

        if(parserErrorDetector.isError) {
            throw JsonPathParserException()
        }

        val abstractSyntaxTree = AntlrJsonPathSemanticAnalyzerVisitor(
            errorListener = errorListener,
            functionExtensionRetriever = functionExtensionRetriever,
        ).visit(jsonPathQueryContext)
        val rootValueType = abstractSyntaxTree?.value

        if(rootValueType is JsonPathExpression.ErrorType) {
            throw JsonPathTypeCheckerException("Type errors have occured: $abstractSyntaxTree")
        }
        if(rootValueType !is JsonPathExpression.FilterExpression.NodesExpression.FilterQueryExpression) {
            throw JsonPathTypeCheckerException("Invalid root value type: $rootValueType: $abstractSyntaxTree")
        }

        return object : JsonPathQuery {
            override fun invoke(currentNode: JsonElement, rootNode: JsonElement): NodeList {
                return rootValueType.jsonPathQuery.invoke(
                    currentNode = currentNode,
                    rootNode = rootNode,
                )
            }
        }
    }

    fun setErrorListener(errorListener: AntlrJsonPathCompilerErrorListener?) {
        this.errorListener = errorListener
    }

    fun getErrorListener(): AntlrJsonPathCompilerErrorListener? {
        return errorListener
    }
}