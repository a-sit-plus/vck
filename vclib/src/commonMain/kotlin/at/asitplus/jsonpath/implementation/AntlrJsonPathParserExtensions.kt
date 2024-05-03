package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.Rfc9535Utils
import at.asitplus.jsonpath.generated.JsonPathParser

internal fun JsonPathParser.StringLiteralContext.toUnescapedString(): String {
    return Rfc9535Utils.unpackStringLiteral(this.text)
}

