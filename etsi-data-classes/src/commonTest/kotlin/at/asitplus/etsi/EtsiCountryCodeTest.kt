package at.asitplus.etsi

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldThrow
import kotlin.getValue

@Suppress("unused")
val EtsiCountryCodeTest by testSuite {
    testSuite("must all be uppercase") {
        withData(
            "a",
            "aA"
        ) {
            shouldThrow<IllegalArgumentException> {
                EtsiCountryCode(it)
            }
        }
        withData(
            "A",
            "AA",
            "EU",
            "UK",
            "EL",
        ) {
            EtsiCountryCode(it)
        }
    }
}