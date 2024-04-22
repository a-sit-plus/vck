package at.asitplus.wallet.lib.data.jsonPath

import io.github.aakira.napier.Napier
import org.antlr.v4.kotlinruntime.BaseErrorListener
import org.antlr.v4.kotlinruntime.RecognitionException
import org.antlr.v4.kotlinruntime.Recognizer

class NapierAntlrErrorListener(
    val contextName: String,
) : BaseErrorListener() {
    override fun syntaxError(
        recognizer: Recognizer<*, *>,
        offendingSymbol: Any?,
        line: Int,
        charPositionInLine: Int,
        msg: String,
        e: RecognitionException?
    ) {
        Napier.e("$contextName: Syntax error $line:$charPositionInLine $msg")
    }
}