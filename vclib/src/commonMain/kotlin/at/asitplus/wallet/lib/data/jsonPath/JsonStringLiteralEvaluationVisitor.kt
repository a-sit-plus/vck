package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonStringLiteralParser
import at.asitplus.parser.generated.JsonStringLiteralParserBaseVisitor

class JsonStringLiteralEvaluationVisitor : JsonStringLiteralParserBaseVisitor<String>() {
    override fun defaultResult(): String {
        return ""
    }
    override fun aggregateResult(aggregate: String?, nextResult: String): String {
        return (aggregate ?: "") + nextResult
    }

    override fun visitString(ctx: JsonStringLiteralParser.StringContext): String {
        return ctx.char().joinToString("") {
            visitChar(it)
        }
    }

    override fun visitChar(ctx: JsonStringLiteralParser.CharContext): String {
        return ctx.UNESCAPED()?.text ?: ctx.escapable()?.let {
            try {
                visitEscapable(it)
            } catch (invalidHexCharException: InvalidHexCharException) {
                throw InvalidCharException(ctx)
            }
        } ?: throw InvalidCharException(ctx)
    }

    override fun visitEscapedDQuote(ctx: JsonStringLiteralParser.EscapedDQuoteContext): String {
        return "\""
    }

    override fun visitEscapedBackslash(ctx: JsonStringLiteralParser.EscapedBackslashContext): String {
        return "\\"
    }

    override fun visitEscapedSlash(ctx: JsonStringLiteralParser.EscapedSlashContext): String {
        return "/"
    }

    override fun visitEscapedLowercaseB(ctx: JsonStringLiteralParser.EscapedLowercaseBContext): String {
        return Char(0x0008).toString() // BS backspace U+0008
    }

    override fun visitEscapedLowercaseF(ctx: JsonStringLiteralParser.EscapedLowercaseFContext): String {
        return Char(0x000c).toString() // FF form feed U+000C
    }

    override fun visitEscapedLowercaseN(ctx: JsonStringLiteralParser.EscapedLowercaseNContext): String {
        return Char(0x000a).toString() // LF line feed U+000A
    }

    override fun visitEscapedLowercaseR(ctx: JsonStringLiteralParser.EscapedLowercaseRContext): String {
        return Char(0x000d).toString() // CR carriage return U+000D
    }

    override fun visitEscapedLowercaseT(ctx: JsonStringLiteralParser.EscapedLowercaseTContext): String {
        return Char(0x0009).toString() // HT horizontal tab U+0009
    }

    override fun visitHexchar(ctx: JsonStringLiteralParser.HexcharContext): String {
        return Char(ctx.NON_SURROGATE()?.text?.toInt(16) ?: run {
            // see https://en.wikipedia.org/wiki/UTF-16#Examples
            val highSurrogate = ctx.HIGH_SURROGATE()?.text?.toInt(16)
            val lowSurrogate = ctx.LOW_SURROGATE()?.text?.toInt(16)

            if(highSurrogate == null) {
                throw InvalidHexCharException(ctx)
            }
            if(lowSurrogate == null) {
                throw InvalidHexCharException(ctx)
            }
            (highSurrogate - 0xD800) * 0x400 + (lowSurrogate - 0xDC00) + 0x10000
        }).toString()
    }
}

open class JSONStringLiteralParserException(message: String) : Exception(message)

class InvalidCharException(ctx: JsonStringLiteralParser.CharContext) : JSONStringLiteralParserException(
    "Invalid char: ${ctx.text}"
)

class InvalidHexCharException(ctx: JsonStringLiteralParser.HexcharContext) : JSONStringLiteralParserException(
    "Invalid hexchar: \\u${ctx.text}"
)