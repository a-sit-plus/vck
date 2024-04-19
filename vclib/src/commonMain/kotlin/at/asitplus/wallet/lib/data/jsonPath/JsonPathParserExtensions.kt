package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser

fun JsonPathParser.StringLiteralContext.toUnescapedString(): String {
    return rfc9535Utils.unpackStringLiteral(this.text)
}

