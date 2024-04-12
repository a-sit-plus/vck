package at.asitplus.wallet.lib.data.JSONPath

import io.ktor.http.quote
import kotlinx.serialization.json.JsonObject
import org.antlr.v4.kotlinruntime.ParserRuleContext

// specification: https://datatracker.ietf.org/doc/rfc9535/
open class JSONPathParserException(message: String) : Exception(message)

class UnexpectedTokenException(ctx: ParserRuleContext) : Exception(
    "Unexpected text at position ${ctx.position?.let { "${it.start.line}:${it.start.column}" }}: \"${ctx.text.quote()}\""
)

class MissingKeyException(jsonObject: JsonObject, key: String) : Exception(
    "Missing key \"${key.quote()}\" at object \"${jsonObject.toString().quote()}\""
)

class InvalidJSONPathParserException(val jsonPath: String) : JSONPathParserException("Invalid JSONPath: $jsonPath")

class UnknownFunctionExtensionException(functionExtensionName: String) :
    Exception(functionExtensionName)