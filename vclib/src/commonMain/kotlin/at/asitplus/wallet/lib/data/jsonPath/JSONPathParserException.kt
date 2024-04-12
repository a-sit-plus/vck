package at.asitplus.wallet.lib.data.jsonPath

import io.ktor.http.quote
import kotlinx.serialization.json.JsonObject
import org.antlr.v4.kotlinruntime.ParserRuleContext

// specification: https://datatracker.ietf.org/doc/rfc9535/
open class JSONPathParserException(message: String) : Exception(message)

class UnexpectedTokenException(ctx: ParserRuleContext) : JSONPathParserException(
    "Unexpected text at position ${ctx.position?.let { "${it.start.line}:${it.start.column}" }}: \"${ctx.text.quote()}\""
)

class MissingKeyException(jsonObject: JsonObject, key: String) : JSONPathParserException(
    "Missing key \"${key.quote()}\" at object \"${jsonObject.toString().quote()}\""
)

class UnknownFunctionExtensionException(functionExtensionName: String) :JSONPathParserException(
    "Unknown function extension: $functionExtensionName"
)

class InvalidValueException(value: JSONPathFilterExpressionValue) :JSONPathParserException(
    "Test expression must either result in NodeListValue or a LogicalValue, but received: $value"
)