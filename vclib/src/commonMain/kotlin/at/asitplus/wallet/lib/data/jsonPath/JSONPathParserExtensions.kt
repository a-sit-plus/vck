package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JSONPathParser

fun JSONPathParser.StringLiteralContext.toUnescapedString(): String {
    val withoutQuotesAtEnds = this.text.substring(1, this.text.lastIndex)

    val out = StringBuilder()
    var isEscaped = false

    for (c in withoutQuotesAtEnds.toCharArray()) {
        if (isEscaped) {
            out.append(c)
            isEscaped = false
        } else if (c == '\\') {  // TODO: find a way to get the escape symbol?
            isEscaped = true
        } else {
            out.append(c)
        }
    }
    return out.toString()
}