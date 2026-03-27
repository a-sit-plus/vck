package at.asitplus.rfc6749OAuth2AuthorizationFramework

import at.asitplus.testballoon.invoke
import at.asitplus.testballoon.minus
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.assertions.throwables.shouldThrowWithMessage

@Suppress("unused")
val ResponseTypeNameCharTest by testSuite {
    "_ is allowed" {
        shouldNotThrowAny {
            ResponseTypeNameChar('_')
        }
    }
    "ALPHA is allowed" - {
        withData(('a'..'z').toList() + ('A'..'Z').toList()) {
            shouldNotThrowAny {
                ResponseTypeNameChar(it)
            }
        }
    }
    "DIGIT is allowed" - {
        withData(('0'..'9').toList()) {
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