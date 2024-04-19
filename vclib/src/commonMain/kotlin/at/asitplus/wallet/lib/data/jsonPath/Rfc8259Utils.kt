package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonStringLiteralLexer
import at.asitplus.parser.generated.JsonStringLiteralParser
import org.antlr.v4.kotlinruntime.CharStreams
import org.antlr.v4.kotlinruntime.CommonTokenStream

interface Rfc8259Utils {
    fun unpackStringLiteral(string: String): String
}

val rfc8259Utils by lazy {
    object : Rfc8259Utils {
        override fun unpackStringLiteral(string: String): String {
            val lexer = JsonStringLiteralLexer(CharStreams.fromString(string)).apply {
                addErrorListener(NapierJsonPathCompilerErrorListener("JSONStringLiteralLexer"))
            }
            val tokenStream = CommonTokenStream(lexer)
            val parser = JsonStringLiteralParser(tokenStream).apply {
                addErrorListener(NapierJsonPathCompilerErrorListener("JSONStringLiteralParser"))
            }

            return JsonStringLiteralEvaluationVisitor().visitString(parser.string())
        }
    }
}