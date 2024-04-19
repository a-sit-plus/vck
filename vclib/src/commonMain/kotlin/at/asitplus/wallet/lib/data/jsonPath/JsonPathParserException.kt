package at.asitplus.wallet.lib.data.jsonPath

import io.ktor.http.quote
import kotlinx.serialization.json.JsonObject
import org.antlr.v4.kotlinruntime.ParserRuleContext

// specification: https://datatracker.ietf.org/doc/rfc9535/


open class JsonPathParserException(message: String) : Exception(message)

open class JsonPathTypeCheckerException(message: String) : JsonPathParserException(message)

open class JsonPathRuntimeException(message: String) : JsonPathParserException(message)

class UnexpectedTokenException(ctx: ParserRuleContext) : JsonPathRuntimeException(
    "Unexpected text at position ${ctx.position?.let { "${it.start.line}:${it.start.column}" }}: \"${ctx.text.quote()}\""
)

class InvalidTestExpressionValueException(expression: ParserRuleContext, value: JsonPathExpressionValue?) : JsonPathRuntimeException(
    "Invalid test expression value at position ${expression.position?.let { "${it.start.line}:${it.start.column}" }}: ${expression.toString().quote()} results in: ${value.toString().quote()}"
)

class InvalidComparableValueException(expression: ParserRuleContext, value: JsonPathExpressionValue) : JsonPathRuntimeException(
    "Invalid expression value at position ${expression.position?.let { "${it.start.line}:${it.start.column}" }}: ${expression.toString().quote()} results in: ${value.toString().quote()}"
)

class MissingKeyException(jsonObject: JsonObject, key: String) : JsonPathRuntimeException(
    "Missing key \"${key.quote()}\" at object \"${jsonObject.toString().quote()}\""
)

class UnknownFunctionExtensionException(functionExtensionName: String) :JsonPathRuntimeException(
    "Unknown function extension: $functionExtensionName"
)

class InvalidArgumentsException(val expectedArguments: Int, val actualArguments: Int) : Exception(
    "Invalid number of arguments. Expected $expectedArguments, but received $actualArguments."
)
class InvalidArgumentTypeException(val value: JsonPathExpressionValue, val expectedArgumentType: JsonPathExpressionTypeEnum): JsonPathTypeCheckerException(
    "Unexpected argument type: Expected value of type ${expectedArgumentType.toString().quote()}, received: $value"
)