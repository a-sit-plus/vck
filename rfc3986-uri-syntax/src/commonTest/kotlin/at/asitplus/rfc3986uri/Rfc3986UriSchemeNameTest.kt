package at.asitplus.rfc3986uri

import at.asitplus.testballoon.matrix.*
import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986UriSchemeNameTest by matrixSuite {
    test("case insensitivity") {
        Rfc3986UriSchemeName("aaAA") shouldBe Rfc3986UriSchemeName("aAaA")
    }

    testSuite("starts with letter") {
        listOf("123", "+aa", "-a", ".a").asData() test {
            shouldThrow<IllegalArgumentException> {
                Rfc3986UriSchemeName(it)
            }
        }
    }
}
