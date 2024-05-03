package at.asitplus.jsonpath

import at.asitplus.jsonpath.core.JsonPathCompiler
import at.asitplus.jsonpath.core.JsonPathFilterExpressionType
import at.asitplus.jsonpath.core.JsonPathFunctionExtension
import at.asitplus.jsonpath.core.functionExtensions.LengthFunctionExtension
import at.asitplus.jsonpath.core.functionExtensions.MatchFunctionExtension
import at.asitplus.jsonpath.core.functionExtensions.SearchFunctionExtension
import at.asitplus.jsonpath.core.functionExtensions.ValueFunctionExtension
import at.asitplus.jsonpath.implementation.AntlrJsonPathCompiler
import at.asitplus.jsonpath.implementation.AntlrJsonPathCompilerErrorListener
import at.asitplus.wallet.lib.data.jsonpath.functionExtensions.CountFunctionExtension
import io.github.aakira.napier.Napier
import org.antlr.v4.kotlinruntime.BaseErrorListener
import org.antlr.v4.kotlinruntime.RecognitionException
import org.antlr.v4.kotlinruntime.Recognizer

object JsonPathDependencyManager {
    /**
     * Function extension repository that may be extended with custom functions by the user of this library.
     */
    var functionExtensionRepository: JsonPathFunctionExtensionRepository =
        JsonPathFunctionExtensionMapRepository(
            listOf(
                LengthFunctionExtension,
                CountFunctionExtension,
                MatchFunctionExtension,
                SearchFunctionExtension,
                ValueFunctionExtension,
            ).associateBy {
                it.name
            }.toMutableMap()
        )

    /**
     * Implementations should support the case where the function extensions change before executing the resulting query.
     * Implementations should use the above mentioned function extension repository as a source of function extensions.
     */
    var compiler: JsonPathCompiler = run {
        val napierAntlrJsonPathCompilerErrorListener =
            object : AntlrJsonPathCompilerErrorListener, BaseErrorListener() {
                override fun unknownFunctionExtension(functionExtensionName: String) {
                    Napier.e("Unknown JSONPath function extension: \"$functionExtensionName\"")
                }

                override fun invalidFunctionExtensionForTestExpression(functionExtensionName: String) {
                    Napier.e("Invalid JSONPath function extension return type for test expression: \"$functionExtensionName\"")
                }

                override fun invalidFunctionExtensionForComparable(functionExtensionName: String) {
                    Napier.e("Invalid JSONPath function extension return type for test expression: \"$functionExtensionName\"")
                }

                override fun invalidArglistForFunctionExtension(
                    functionExtension: JsonPathFunctionExtension<*>,
                    coercedArgumentTypes: List<Pair<JsonPathFilterExpressionType?, String>>
                ) {
                    Napier.e(
                        "Invalid arguments for function extension \"${functionExtension.name}\": Expected: <${
                            functionExtension.argumentTypes.joinToString(
                                ", "
                            )
                        }>, but received <${
                            coercedArgumentTypes.map { it.first }.joinToString(", ")
                        }>: <${coercedArgumentTypes.map { it.second }.joinToString(", ")}>"
                    )
                }

                override fun invalidTestExpression(testContextString: String) {
                    Napier.e("Invalid test expression: $testContextString")
                }

                override fun syntaxError(
                    recognizer: Recognizer<*, *>,
                    offendingSymbol: Any?,
                    line: Int,
                    charPositionInLine: Int,
                    msg: String,
                    e: RecognitionException?
                ) {
                    Napier.e("Syntax error $line:$charPositionInLine $msg")
                }
            }


        AntlrJsonPathCompiler(
            errorListener = napierAntlrJsonPathCompilerErrorListener,
            functionExtensionRetriever = {
                functionExtensionRepository.getExtension(it)
            }
        )
    }
}