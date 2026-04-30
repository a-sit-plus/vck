package at.asitplus.etsi

import de.infix.testBalloon.framework.core.testSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc6838MimeTypeTest by testSuite {
    test("case insensitivity") {
        Rfc6838MimeType("aaAA") shouldBe Rfc6838MimeType("aAaA")
    }
}

