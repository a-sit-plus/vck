package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowWithMessage

@Suppress("unused")
val ResponseTypeNameCharTest by matrixSuite {
    "_ is allowed" {
        shouldNotThrowAny {
            ResponseTypeNameChar('_')
        }
    }
    "ALPHA is allowed" - {
        data(('a'..'z').toList() + ('A'..'Z').toList()) test {
            shouldNotThrowAny {
                ResponseTypeNameChar(it)
            }
        }
    }
    "DIGIT is allowed" - {
        data(('0'..'9').toList()) test {
            shouldNotThrowAny {
                ResponseTypeNameChar(it)
            }
        }
    }
    "other ANSI characters are NOT allowed" {
        (0..127).forEach { charCode ->
            val it = Char(charCode)
            if(it != '_' && it !in 'a'..'z' && it !in 'A'..'Z' && it !in '0'..'9') {
                try {
                    ResponseTypeNameChar(it)
                    throw AssertionError("$charCode")
                } catch (_: IllegalArgumentException) {
                    // this is expected to happen
                }
            }
        }
    }
}