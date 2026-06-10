package at.asitplus.openid.dcql

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

val DCQLCredentialQueryIdentifierTest by matrixSuite {
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
            ).asData() test {
            shouldThrow<IllegalArgumentException> {
                DCQLClaimsQueryIdentifier(it)
            }
        }
    }
}