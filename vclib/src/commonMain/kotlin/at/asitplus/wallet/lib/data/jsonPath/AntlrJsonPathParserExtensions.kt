package at.asitplus.wallet.lib.data.jsonPath

import at.asitplus.parser.generated.JsonPathParser

fun JsonPathParser.StringLiteralContext.toUnescapedString(): String {
    return Rfc9535Utils.unpackStringLiteral(this.text)
}

