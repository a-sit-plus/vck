package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

@Suppress("unused")
val SvgContentPlaceholderTest by matrixSuite {
    testSuite("valid placeholders are accepted") {
        data(listOf("name", "address_street_address", "claim_1", "addr2", "a1b2c3", "_private", "_0", "A", "camelCase42")) test {
            shouldNotThrowAny { SvgContentPlaceholder(it) }
        }
    }

    testSuite("invalid placeholders are rejected") {
        data(listOf("1claim", "0", "42abc")) test {
            shouldThrow<IllegalArgumentException> { SvgContentPlaceholder(it) }
        }
    }
}
