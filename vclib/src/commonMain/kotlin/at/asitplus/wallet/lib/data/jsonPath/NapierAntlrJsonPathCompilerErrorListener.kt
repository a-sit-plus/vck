package at.asitplus.wallet.lib.data.jsonPath

import com.strumenta.antlrkotlin.runtime.BitSet
import io.github.aakira.napier.Napier
import org.antlr.v4.kotlinruntime.Parser
import org.antlr.v4.kotlinruntime.RecognitionException
import org.antlr.v4.kotlinruntime.Recognizer
import org.antlr.v4.kotlinruntime.atn.ATNConfigSet
import org.antlr.v4.kotlinruntime.dfa.DFA

val napierAntlrJsonPathCompilerErrorListener by lazy {
    val napierAntlrErrorListener = NapierAntlrErrorListener("JsonPath Compiler")

    object : AntlrJsonPathCompilerErrorListener {
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
            coercedArgumentTypes: List<JsonPathExpressionType?>
        ) {
            Napier.e(
                "Invalid arguments for function extension \"${functionExtension.name}\": Expected: <${
                    functionExtension.argumentTypes.joinToString(
                        ", "
                    )
                }>, but received <${coercedArgumentTypes.joinToString(", ")}>"
            )
        }

        override fun reportAmbiguity(
            recognizer: Parser,
            dfa: DFA,
            startIndex: Int,
            stopIndex: Int,
            exact: Boolean,
            ambigAlts: BitSet,
            configs: ATNConfigSet
        ) {
            napierAntlrErrorListener.reportAmbiguity(
                recognizer = recognizer,
                dfa = dfa,
                startIndex = startIndex,
                stopIndex = stopIndex,
                exact = exact,
                ambigAlts = ambigAlts,
                configs = configs,
            )
        }

        override fun reportAttemptingFullContext(
            recognizer: Parser,
            dfa: DFA,
            startIndex: Int,
            stopIndex: Int,
            conflictingAlts: BitSet,
            configs: ATNConfigSet
        ) {
            napierAntlrErrorListener.reportAttemptingFullContext(
                recognizer = recognizer,
                dfa = dfa,
                startIndex = startIndex,
                stopIndex = stopIndex,
                conflictingAlts = conflictingAlts,
                configs = configs,
            )
        }

        override fun reportContextSensitivity(
            recognizer: Parser,
            dfa: DFA,
            startIndex: Int,
            stopIndex: Int,
            prediction: Int,
            configs: ATNConfigSet
        ) {
            napierAntlrErrorListener.reportContextSensitivity(
                recognizer = recognizer,
                dfa = dfa,
                startIndex = startIndex,
                stopIndex = stopIndex,
                prediction = prediction,
                configs = configs,
            )
        }

        override fun syntaxError(
            recognizer: Recognizer<*, *>,
            offendingSymbol: Any?,
            line: Int,
            charPositionInLine: Int,
            msg: String,
            e: RecognitionException?
        ) {
            napierAntlrErrorListener.syntaxError(
                recognizer = recognizer,
                offendingSymbol = offendingSymbol,
                line = line,
                charPositionInLine = charPositionInLine,
                msg = msg,
                e = e,
            )
        }
    }
}