package at.asitplus.wallet.sdjwt

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow

@Suppress("unused")
val SvgContentPlaceholderTest by matrixSuite {
    testSuite("valid placeholders are accepted") {
        listOf("name", "address_street_address", "claim_1", "addr2", "a1b2c3", "_private", "_0", "A", "camelCase42").asData() test {
            shouldNotThrowAny { SvgContentPlaceholder(it) }
        }
    }

    testSuite("invalid placeholders are rejected") {
        listOf("1claim", "0", "42abc").asData() test {
            shouldThrow<IllegalArgumentException> { SvgContentPlaceholder(it) }
        }
    }
}
