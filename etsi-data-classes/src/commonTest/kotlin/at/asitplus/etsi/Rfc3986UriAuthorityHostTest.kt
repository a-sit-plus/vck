package at.asitplus.etsi

import at.asitplus.rfc.Rfc3986AuthorityHost
import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986AuthorityHostTest by testSuite {
    testSuite("case insensitivity") {
        withData(
            mapOf(
                "v6 simple" to Pair("aaAA", "aAaA"),
            )
        ) {
            Rfc3986AuthorityHost("[${it.first}]") shouldBe Rfc3986AuthorityHost("[${it.second}]")
        }
    }

    testSuite("parsing success") {
        withData(
            "www.ietf.org",
            "[aaAA::]",
            "127.0.0.1",
            "v1.a",
        ) {it ->
            shouldNotThrowAny {
                Rfc3986AuthorityHost(it)
            }
        }
    }
}
