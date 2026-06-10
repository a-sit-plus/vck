package at.asitplus.etsi

import at.asitplus.testballoon.matrix.matrixSuite
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc6838MimeTypeTest by matrixSuite {
    test("case insensitivity") {
        Rfc6838MimeType("aaAA") shouldBe Rfc6838MimeType("aAaA")
    }
}

