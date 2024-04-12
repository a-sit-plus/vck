package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

fun JSONPathParser.StringLiteralContext.toUnescapedString(): String {
    // !! because we know per grammar rules that either must be not null
    return singleQuotedLiteral()?.singleQuoted()?.joinToString("") {
        listOfNotNull(
            it.unescaped()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.escapable()?.text,
        ).joinToString("")
    } ?: doubleQuotedLiteral()!!.doubleQuoted().joinToString("") {
        listOfNotNull(
            it.unescaped()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.escapable()?.text,
        ).joinToString("")
    }
}