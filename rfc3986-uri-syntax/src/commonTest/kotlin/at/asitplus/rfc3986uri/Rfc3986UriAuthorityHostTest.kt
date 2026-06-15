package at.asitplus.rfc3986uri

import at.asitplus.testballoon.withData
import de.infix.testBalloon.framework.core.testSuite
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe

@Suppress("unused")
val Rfc3986AuthorityHostTest by testSuite {
    testSuite("case insensitivity") {
        withData(
            mapOf(
                "v6 simple" to Pair("aaAA::", "aAaA::"),
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
            "[v1.a]",
            "[vff.test:data]",
        ) {it ->
            shouldNotThrowAny {
                Rfc3986AuthorityHost(it)
            }
        }
    }

    testSuite("IP-literal bracket validation") {
        test("missing closing bracket is rejected") {
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHost("[::1") }
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHost("[v1.foo") }
        }
        test("string without opening bracket is not treated as IP-literal") {
            shouldNotThrowAny { Rfc3986AuthorityHost("example.com") }
        }
    }

    testSuite("IPv4 octet zero") {
        test("single zero octet is valid") {
            shouldNotThrowAny { Rfc3986AuthorityHostIPv4("0.0.0.0") }
            shouldNotThrowAny { Rfc3986AuthorityHostIPv4("192.0.2.0") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://0.0.0.0/") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://192.0.2.128/") }
        }
        test("leading zero in multi-digit octet is rejected") {
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHostIPv4("01.2.3.4") }
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHostIPv4("192.00.2.1") }
        }
    }

    testSuite("IPv6 group count without compression") {
        test("full 8-group address is accepted") {
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("2001:db8:85a3:0:0:8a2e:370:7334") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://[2001:db8:85a3:0:0:8a2e:370:7334]/") }
        }
        test("fewer than 8 groups without :: is rejected") {
            shouldThrow<IllegalArgumentException> { Rfc3986AuthorityHostIPv6("1:2:3") }
            shouldThrow<IllegalArgumentException> { Rfc3986UniformResourceIdentifier("http://[1:2:3]/") }
        }
        test(":: forms with fewer groups are still accepted") {
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("::1") }
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("1::") }
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("::") }
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("2001:db8::1") }
        }
        test("IPv4 tail in full IPv6 literal without :: is accepted") {
            shouldNotThrowAny { Rfc3986AuthorityHostIPv6("0:0:0:0:0:ffff:192.0.2.128") }
            shouldNotThrowAny { Rfc3986UniformResourceIdentifier("http://[0:0:0:0:0:ffff:192.0.2.128]/") }
            Rfc3986AuthorityHostIPv6("0:0:0:0:0:ffff:192.0.2.128").parts.size shouldBe 8
        }
    }

    testSuite("IPvFuture round-trips through URI") {
        withData(
            "http://[v1.foo]/path",
            "http://[vff.test:data]/",
        ) { uri ->
            Rfc3986UniformResourceIdentifier(uri).string shouldBe uri
        }
    }
}

