package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

fun JSONPathParser.String_literalContext.toUnescapedString(): String {
    // !! because we know per grammar rules that either must be not null
    return single_quoted().joinToString("") {
        listOfNotNull(
            it.UNESCAPED()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.escapable()?.text,
        ).joinToString("")
    } + double_quoted().joinToString("") {
        listOfNotNull(
            it.UNESCAPED()?.text,
            it.DQUOTE()?.text,
            it.SQUOTE()?.text,
            it.escapable()?.text,
        ).joinToString("")
    }
}