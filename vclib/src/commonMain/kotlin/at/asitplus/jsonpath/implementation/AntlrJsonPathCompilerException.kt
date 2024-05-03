package at.asitplus.jsonpath.implementation

import at.asitplus.jsonpath.core.JsonPathCompilerException
import at.asitplus.jsonpath.core.JsonPathQueryException
import at.asitplus.jsonpath.core.Rfc9535Utils
import kotlinx.serialization.json.JsonObject

/**
 * specification: https://datatracker.ietf.org/doc/rfc9535/
 * date: 2024-02
 */
internal class JsonPathLexerException : JsonPathCompilerException(
    "Lexer errors have occured. See the output of the error listener for more details"
)

internal class JsonPathParserException : JsonPathCompilerException(
    "Parser errors have occured. See the output of the error listener for more details"
)

internal class JsonPathTypeCheckerException(message: String) : JsonPathCompilerException(message)

internal class MissingKeyException(jsonObject: JsonObject, key: String) : JsonPathQueryException(
    "Missing key ${Rfc9535Utils.escapeToDoubleQuoted(key)} at object ${
        Rfc9535Utils.escapeToDoubleQuoted(
            jsonObject.toString()
        )
    }"
)