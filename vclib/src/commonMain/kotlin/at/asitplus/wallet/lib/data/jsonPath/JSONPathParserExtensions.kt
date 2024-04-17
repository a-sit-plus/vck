package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

fun JSONPathParser.StringLiteralContext.toUnescapedString(): String {
    // !! because we know per grammar rules that either must be not null
    return singleQuoted().joinToString("") {
        listOfNotNull(
            it.UNESCAPED()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.ESCAPABLE()?.text,
        ).joinToString("")
    } + singleQuoted().joinToString("") {
        listOfNotNull(
            it.UNESCAPED()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.ESCAPABLE()?.text,
        ).joinToString("")
    }
}