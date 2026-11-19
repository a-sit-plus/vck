package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

val DCQLClaimsQueryIdentifierTest by matrixSuite {
    "success" - {
        listOf(
                "numberTest0123456789",
                "alphabetTestabcdefghijklmnopqrstuvwxyz",
                "alphabetTestABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "underscore_test",
                "dash-test",
                "dash-underscore_test",
            ).asData() test {
            shouldNotThrowAny {
                DCQLClaimsQueryIdentifier(it)
            }
        }
    }
    "failure" - {
        listOf(
                "invalid_character space",
                "invalid_character.dot",
                "invalid_character:column",
                "invalid_character!exclamationMark",
                "invalid_character\"doubleQuote",
                "invalid_character'singleQuote",
                "non_ascii_letter_\u00e4",
                "non_ascii_letter_\u0434",
                "non_ascii_digit_\u0663",
            ).asData() test {
            shouldThrow<IllegalArgumentException> {
                DCQLClaimsQueryIdentifier(it)
            }
        }
    }
}