package at.asitplus.wallet.lib.data.jsonPath

import io.ktor.http.quote
import kotlinx.serialization.json.JsonObject
import org.antlr.v4.kotlinruntime.ParserRuleContext

// specification: https://datatracker.ietf.org/doc/rfc9535/


open class JSONPathParserException(message: String) : Exception(message)

open class JSONPathTypeCheckerException(message: String) : JSONPathParserException(message)

open class JSONPathRuntimeException(message: String) : JSONPathParserException(message)

class UnexpectedTokenException(ctx: ParserRuleContext) : JSONPathRuntimeException(
    "Unexpected text at position ${ctx.position?.let { "${it.start.line}:${it.start.column}" }}: \"${ctx.text.quote()}\""
)

class InvalidTestExpressionValueException(expression: ParserRuleContext, value: JSONPathFunctionExpressionValue?) : JSONPathRuntimeException(
    "Invalid test expression value at position ${expression.position?.let { "${it.start.line}:${it.start.column}" }}: ${expression.toString().quote()} results in: ${value.toString().quote()}"
)

class InvalidComparableValueException(expression: ParserRuleContext, value: JSONPathFunctionExpressionValue) : JSONPathRuntimeException(
    "Invalid expression value at position ${expression.position?.let { "${it.start.line}:${it.start.column}" }}: ${expression.toString().quote()} results in: ${value.toString().quote()}"
)

class MissingKeyException(jsonObject: JsonObject, key: String) : JSONPathRuntimeException(
    "Missing key \"${key.quote()}\" at object \"${jsonObject.toString().quote()}\""
)

class UnknownFunctionExtensionException(functionExtensionName: String) :JSONPathRuntimeException(
    "Unknown function extension: $functionExtensionName"
)