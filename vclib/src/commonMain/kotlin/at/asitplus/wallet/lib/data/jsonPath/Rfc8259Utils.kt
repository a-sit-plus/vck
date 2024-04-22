package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonStringLiteralLexer
import at.asitplus.parser.generated.JsonStringLiteralParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

interface Rfc8259Utils {
    companion object {
        fun unpackStringLiteral(string: String): String {
            val lexer = JsonStringLiteralLexer(CharStreams.fromString(string)).apply {
                addErrorListener(NapierAntlrErrorListener("JSONStringLiteralLexer"))
            }
            val tokenStream = CommonTokenStream(lexer)
            val parser = JsonStringLiteralParser(tokenStream).apply {
                addErrorListener(NapierAntlrErrorListener("JSONStringLiteralParser"))
            }

            return AntlrJsonStringLiteralEvaluationVisitor().visitString(parser.string())
        }
    }
}