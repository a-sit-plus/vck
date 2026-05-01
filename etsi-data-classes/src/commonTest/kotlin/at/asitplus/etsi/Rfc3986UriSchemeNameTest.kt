package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986UriSchemeName
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986UriSchemeNameTest by testSuite {
    test("case insensitivity") {
        Rfc3986UriSchemeName("aaAA") shouldBe Rfc3986UriSchemeName("aAaA")
    }

    testSuite("starts with letter") {
        withData(
            "123",
            "+aa",
            "-a",
            ".a",
        ) {
            shouldThrow<IllegalArgumentException> {
                Rfc3986UriSchemeName(it)
            }
        }
    }
}
