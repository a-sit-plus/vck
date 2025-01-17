package at.asitplus.openid.dcql

import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FreeSpec
import io.kotest.datatest.withData

class DCQLCredentialQueryIdentifierTest : FreeSpec({
    "success" - {
        withData(
            listOf(
                "numberTest0123456789",
                "alphabetTestabcdefghijklmnopqrstuvwxyz",
                "alphabetTestABCDEFGHIJKLMNOPQRSTUVWXYZ",
                "underscore_test",
                "dash-test",
                "dash-underscore_test",
            )
        ) {
            shouldNotThrowAny {
                DCQLClaimsQueryIdentifier(it)
            }
        }
    }
    "failure" - {
        withData(
            listOf(
                "invalid_character space",
                "invalid_character.dot",
                "invalid_character:column",
                "invalid_character!exclamationMark",
                "invalid_character\"doubleQuote",
                "invalid_character'singleQuote",
            )
        ) {
            shouldThrow<IllegalArgumentException> {
                DCQLClaimsQueryIdentifier(it)
            }
        }
    }
})